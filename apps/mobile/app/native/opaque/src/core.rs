//! The OPAQUE client operations Ruvee's engine uses (`OpaqueClient` in packages/vault), with the
//! D-02 configuration (docs/security/authentication.md §2.2). Each function reproduces the client
//! function of the same name in @serenity-kit/opaque 1.1.0 (src/lib.rs at the tag
//! `@serenity-kit/opaque@1.1.0`), which the web app, the extension and the server use:
//!
//! - cipher suite: ristretto255 OPRF and group, Triple-DH over SHA-512;
//! - key stretching "memory-constrained": Argon2id v1.3, t = 3, m = 2^16 KiB, p = 4, salt of 16
//!   zero bytes;
//! - no client or server identifier, no AKE context; `export_key` is not returned (INV-11);
//! - every message and state is unpadded URL-safe base64 of opaque-ke's serialization;
//! - a login the client itself rejects (wrong password, substituted server, tampered response)
//!   is `Ok(None)`, as upstream; malformed input is an error.
//!
//! Nothing here implements a primitive: the protocol is opaque-ke's, Argon2id is RustCrypto's.

use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64, Engine as _};
use generic_array::{ArrayLength, GenericArray};
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::errors::InternalError;
use opaque_ke::ksf::Ksf;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use rand_core::OsRng;

pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = MemoryConstrained;
}

/// Argon2id with the "memory-constrained" parameters and a zero salt, as upstream's `CustomKsf`.
pub struct MemoryConstrained {
    argon: Argon2<'static>,
}

/// argon2's RECOMMENDED_SALT_LEN, which upstream uses for its zero salt.
const ZERO_SALT: [u8; 16] = [0; 16];

impl Default for MemoryConstrained {
    fn default() -> Self {
        let mut params = ParamsBuilder::default();
        params.t_cost(3);
        params.m_cost(1 << 16);
        params.p_cost(4);
        let params = params.build().expect("fixed Argon2id parameters are valid");
        Self {
            argon: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        }
    }
}

impl Ksf for MemoryConstrained {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::default();
        self.argon
            .hash_password_into(&input, &ZERO_SALT, &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

/// Malformed input or a protocol failure that is not a rejected login. Carries no detail: the
/// caller reports one generic error, and nothing about the input reaches a log.
#[derive(Debug, PartialEq, Eq)]
pub struct OpaqueError;

fn decode(text: &str) -> Result<Vec<u8>, OpaqueError> {
    BASE64.decode(text).map_err(|_| OpaqueError)
}

fn no_identifiers() -> Identifiers<'static> {
    Identifiers {
        client: None,
        server: None,
    }
}

pub struct Started {
    pub state: String,
    pub request: String,
}

/// `startClientRegistration({ password })`.
pub fn start_registration(password: &[u8]) -> Result<Started, OpaqueError> {
    let started = ClientRegistration::<Suite>::start(&mut OsRng, password).map_err(|_| OpaqueError)?;
    Ok(Started {
        state: BASE64.encode(started.state.serialize()),
        request: BASE64.encode(started.message.serialize()),
    })
}

/// `finishClientRegistration({ ..., keyStretching: 'memory-constrained' }).registrationRecord`.
pub fn finish_registration(
    state: &str,
    response: &str,
    password: &[u8],
) -> Result<String, OpaqueError> {
    let ksf = MemoryConstrained::default();
    let state = ClientRegistration::<Suite>::deserialize(&decode(state)?).map_err(|_| OpaqueError)?;
    let response =
        RegistrationResponse::<Suite>::deserialize(&decode(response)?).map_err(|_| OpaqueError)?;
    let finished = state
        .finish(
            &mut OsRng,
            password,
            response,
            ClientRegistrationFinishParameters::new(no_identifiers(), Some(&ksf)),
        )
        .map_err(|_| OpaqueError)?;
    Ok(BASE64.encode(finished.message.serialize()))
}

/// `startClientLogin({ password })`.
pub fn start_login(password: &[u8]) -> Result<Started, OpaqueError> {
    let started = ClientLogin::<Suite>::start(&mut OsRng, password).map_err(|_| OpaqueError)?;
    Ok(Started {
        state: BASE64.encode(started.state.serialize()),
        request: BASE64.encode(started.message.serialize()),
    })
}

/// `finishClientLogin({ ..., keyStretching: 'memory-constrained' })?.finishLoginRequest`.
/// `Ok(None)` when the client rejects the server's response, exactly where upstream returns
/// `undefined`.
pub fn finish_login(
    state: &str,
    response: &str,
    password: &[u8],
) -> Result<Option<String>, OpaqueError> {
    let ksf = MemoryConstrained::default();
    let response =
        CredentialResponse::<Suite>::deserialize(&decode(response)?).map_err(|_| OpaqueError)?;
    let state = ClientLogin::<Suite>::deserialize(&decode(state)?).map_err(|_| OpaqueError)?;
    match state.finish(
        &mut OsRng,
        password,
        response,
        ClientLoginFinishParameters::new(None, no_identifiers(), Some(&ksf)),
    ) {
        Ok(finished) => Ok(Some(BASE64.encode(finished.message.serialize()))),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{
        CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
        ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
    };

    /// The server half here is opaque-ke's own, for a local round trip only. Interoperability
    /// with @serenity-kit/opaque is checked against its Node build (scripts/opaque-interop.mjs)
    /// and against the real API on the device.
    #[test]
    fn round_trip_wrong_password_and_substituted_setup() {
        let setup = ServerSetup::<Suite>::new(&mut OsRng);
        let user = b"synthetic@example.test";
        let password = "synthetic lantern 58 \u{00e9}\u{1f511}".as_bytes();

        let reg = start_registration(password).unwrap();
        let reg_response = ServerRegistration::<Suite>::start(
            &setup,
            RegistrationRequest::deserialize(&decode(&reg.request).unwrap()).unwrap(),
            user,
        )
        .unwrap();
        let record = finish_registration(
            &reg.state,
            &BASE64.encode(reg_response.message.serialize()),
            password,
        )
        .unwrap();
        let record = ServerRegistration::<Suite>::finish(
            RegistrationUpload::deserialize(&decode(&record).unwrap()).unwrap(),
        );

        let login = |pw: &[u8], setup: &ServerSetup<Suite>| {
            let started = start_login(pw).unwrap();
            let server = ServerLogin::start(
                &mut OsRng,
                setup,
                Some(record.clone()),
                CredentialRequest::deserialize(&decode(&started.request).unwrap()).unwrap(),
                user,
                ServerLoginParameters::default(),
            )
            .unwrap();
            let finish = finish_login(
                &started.state,
                &BASE64.encode(server.message.serialize()),
                pw,
            )
            .unwrap();
            (finish, server.state)
        };

        let (finish, state) = login(password, &setup);
        let finish = finish.expect("right password");
        state
            .finish(
                CredentialFinalization::deserialize(&decode(&finish).unwrap()).unwrap(),
                ServerLoginParameters::default(),
            )
            .expect("server accepts the finalization");

        assert_eq!(login(b"not the password", &setup).0, None);
        assert_eq!(login(password, &ServerSetup::<Suite>::new(&mut OsRng)).0, None);
        assert_eq!(finish_login("!!", "!!", password), Err(OpaqueError));
    }
}
