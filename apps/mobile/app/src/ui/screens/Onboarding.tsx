import { useEffect, useRef, useState } from 'react';
import { parseServerOrigin } from '../../platform/server-url';
import { UiError, type LockReason, type VaultApp } from '../../vault/useVaultApp';
import { Banner, Body, Button, Field, Heading, Screen } from '../kit';
import { messageFor } from '../messages';

function errorText(e: unknown): string {
  return e instanceof UiError ? messageFor(e.code, e.retryAfterSeconds) : messageFor('internal');
}

export function ServerScreen({ app }: { app: VaultApp }) {
  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = () => {
    const parsed = parseServerOrigin(value, __DEV__);
    if ('problem' in parsed) {
      setError(
        parsed.problem === 'insecure'
          ? 'Use an https:// address. Plain http is allowed only for this device itself in development builds.'
          : 'Enter the address of your Ruvee server, like https://vault.example.com.',
      );
      return;
    }
    setBusy(true);
    setError(null);
    app.setServer(parsed.origin).catch((e: unknown) => {
      setError(errorText(e));
      setBusy(false);
    });
  };
  return (
    <Screen>
      <Heading>Connect to your server</Heading>
      <Body>Ruvee is self-hosted. Enter the address of the server you use in your browser.</Body>
      <Banner tone="caution">
        Development build. Use synthetic data only; never store real passwords.
      </Banner>
      <Field
        label="Server address"
        testID="server-url"
        value={value}
        onChangeText={setValue}
        autoCapitalize="none"
        keyboardType="url"
        placeholder="https://vault.example.com"
        onSubmitEditing={submit}
      />
      {error ? (
        <Banner tone="danger" testID="server-error">
          {error}
        </Banner>
      ) : null}
      <Button title="Continue" testID="server-continue" busy={busy} onPress={submit} />
    </Screen>
  );
}

export function SignInScreen({ app }: { app: VaultApp }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = () => {
    setBusy(true);
    setError(null);
    // Let the spinner render: OPAQUE's key stretching runs on this thread.
    setTimeout(() => {
      app.signIn(username, password).then(
        () => {
          setPassword('');
        },
        (e: unknown) => {
          setError(errorText(e));
          setBusy(false);
        },
      );
    }, 50);
  };
  return (
    <Screen>
      <Heading>Log in</Heading>
      <Body>
        Log in to {app.origin ?? 'your server'}. This phone becomes a new device; you approve it
        from a device you already use.
      </Body>
      <Field
        label="Username"
        testID="signin-username"
        value={username}
        onChangeText={setUsername}
        autoCapitalize="none"
      />
      <Field
        label="Master password"
        testID="signin-password"
        value={password}
        onChangeText={setPassword}
        secureTextEntry
        autoCapitalize="none"
        textContentType="password"
        onSubmitEditing={submit}
      />
      {error ? (
        <Banner tone="danger" testID="signin-error">
          {error}
        </Banner>
      ) : null}
      <Button
        title="Log in"
        testID="signin-submit"
        busy={busy}
        onPress={submit}
        disabled={!username || !password}
      />
      <Button
        title="Use another server"
        testID="signin-change-server"
        kind="secondary"
        onPress={() => void app.changeServer()}
      />
    </Screen>
  );
}

export function PairScreen({ app, username }: { app: VaultApp; username: string }) {
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [needsPassword, setNeedsPassword] = useState(false);
  const [waiting, setWaiting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    app.needsPairingPassword().then(setNeedsPassword, () => {
      setNeedsPassword(true);
    });
    return () => {
      alive.current = false;
    };
  }, [app]);

  useEffect(() => {
    if (!waiting) return;
    let timer: ReturnType<typeof setTimeout>;
    const poll = () => {
      app.pairingStep().then(
        (done) => {
          if (!done && alive.current) timer = setTimeout(poll, 2000);
        },
        (e: unknown) => {
          if (!alive.current) return;
          setWaiting(false);
          setError(errorText(e));
        },
      );
    };
    poll();
    return () => {
      clearTimeout(timer);
    };
  }, [waiting, app]);

  const submit = () => {
    setBusy(true);
    setError(null);
    setTimeout(() => {
      app.joinPairing(code.trim(), needsPassword ? password : undefined).then(
        () => {
          setPassword('');
          setBusy(false);
          setWaiting(true);
        },
        (e: unknown) => {
          setError(errorText(e));
          setBusy(false);
        },
      );
    }, 50);
  };

  return (
    <Screen>
      <Heading>Add this device</Heading>
      <Body>
        Signed in as {username}. On a device you already use, open Devices, choose “Add a device”
        and type the pairing code it shows here.
      </Body>
      {waiting ? (
        <Banner testID="pair-waiting">Waiting for approval on your other device…</Banner>
      ) : (
        <>
          <Field
            label="Pairing code"
            testID="pair-code"
            value={code}
            onChangeText={setCode}
            autoCapitalize="characters"
            placeholder="PC1-…"
          />
          {needsPassword ? (
            <Field
              label="Master password"
              testID="pair-password"
              value={password}
              onChangeText={setPassword}
              secureTextEntry
              autoCapitalize="none"
            />
          ) : null}
          <Button
            title="Add this device"
            testID="pair-submit"
            busy={busy}
            onPress={submit}
            disabled={!code}
          />
        </>
      )}
      {error ? (
        <Banner tone="danger" testID="pair-error">
          {error}
        </Banner>
      ) : null}
    </Screen>
  );
}

const LOCK_REASON: Record<LockReason, string> = {
  manual: 'Locked.',
  background: 'Locked when Ruvee left the screen.',
  idle: 'Locked after 15 minutes without activity.',
  session_expired: 'Your session ended. Unlock again to continue.',
  logout: 'Logged out of the server. Your encrypted copy stays on this device.',
};

export function UnlockScreen({
  app,
  username,
  reason,
}: {
  app: VaultApp;
  username: string;
  reason?: LockReason;
}) {
  const [password, setPassword] = useState('');
  const [previous, setPrevious] = useState('');
  const [needsPrevious, setNeedsPrevious] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = () => {
    setBusy(true);
    setError(null);
    setTimeout(() => {
      app.unlock(password, needsPrevious ? previous : undefined).then(
        () => {
          setPassword('');
          setPrevious('');
        },
        (e: unknown) => {
          if (e instanceof UiError && e.code === 'previous_password_required')
            setNeedsPrevious(true);
          setError(errorText(e));
          setBusy(false);
        },
      );
    }, 50);
  };
  return (
    <Screen>
      <Heading>Unlock Ruvee</Heading>
      <Body muted>{username}</Body>
      {reason ? <Banner testID="lock-reason">{LOCK_REASON[reason]}</Banner> : null}
      <Field
        label="Master password"
        testID="unlock-password"
        value={password}
        onChangeText={setPassword}
        secureTextEntry
        autoCapitalize="none"
        textContentType="password"
        onSubmitEditing={submit}
      />
      {needsPrevious ? (
        <Field
          label="Previous master password"
          testID="unlock-previous-password"
          value={previous}
          onChangeText={setPrevious}
          secureTextEntry
          autoCapitalize="none"
        />
      ) : null}
      {error ? (
        <Banner tone="danger" testID="unlock-error">
          {error}
        </Banner>
      ) : null}
      <Button
        title="Unlock"
        testID="unlock-submit"
        busy={busy}
        onPress={submit}
        disabled={!password}
      />
    </Screen>
  );
}

export function RevokedScreen({ app }: { app: VaultApp }) {
  return (
    <Screen>
      <Heading>This device was removed</Heading>
      <Body>{messageFor('device_revoked')}</Body>
      <Button
        title="Set up again"
        testID="revoked-start-again"
        onPress={() => void app.startAgain()}
      />
    </Screen>
  );
}

export function FatalScreen({ message }: { message: string }) {
  return (
    <Screen>
      <Heading>Ruvee can't start</Heading>
      <Banner tone="danger" testID="fatal">
        A safety check failed ({message}). Nothing was opened or changed. Reinstall the app or
        contact the person who runs your server.
      </Banner>
    </Screen>
  );
}
