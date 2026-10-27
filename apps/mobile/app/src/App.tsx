import { useState } from 'react';
import { Pressable, StatusBar, StyleSheet, Text, View } from 'react-native';
import { color } from './ui/theme';
import {
  FatalScreen,
  PairScreen,
  RevokedScreen,
  ServerScreen,
  SignInScreen,
  UnlockScreen,
} from './ui/screens/Onboarding';
import { VaultScreen } from './ui/screens/Vault';
import { useVaultApp } from './vault/useVaultApp';

export default function App() {
  const app = useVaultApp();
  const [compat, setCompat] = useState(false);

  if (__DEV__ && compat) {
    const { CompatScreen } =
      require('./compat/CompatScreen') as typeof import('./compat/CompatScreen');
    return <CompatScreen onClose={() => setCompat(false)} />;
  }

  const screen = app.screen;
  return (
    // Any touch counts as activity for the 15-minute lock; it never claims the responder.
    <View
      style={styles.root}
      onStartShouldSetResponderCapture={() => {
        app.touched();
        return false;
      }}
    >
      <StatusBar barStyle="dark-content" />
      {screen.name === 'boot' ? <View style={styles.root} /> : null}
      {screen.name === 'fatal' ? <FatalScreen message={screen.message} /> : null}
      {screen.name === 'server' ? <ServerScreen app={app} /> : null}
      {screen.name === 'signin' ? <SignInScreen app={app} /> : null}
      {screen.name === 'pair' ? <PairScreen app={app} username={screen.username} /> : null}
      {screen.name === 'locked' ? (
        <UnlockScreen
          app={app}
          username={screen.username}
          {...(screen.reason ? { reason: screen.reason } : {})}
        />
      ) : null}
      {screen.name === 'vault' ? <VaultScreen app={app} /> : null}
      {screen.name === 'revoked' ? <RevokedScreen app={app} /> : null}
      {__DEV__ && (screen.name === 'server' || screen.name === 'signin') ? (
        <Pressable
          testID="open-compat"
          onPress={() => setCompat(true)}
          accessibilityRole="button"
          style={styles.dev}
        >
          <Text style={styles.devText}>Native compatibility checks (development)</Text>
        </Pressable>
      ) : null}
      {/* While the system shows the app switcher or a dialog, cover the vault. */}
      {app.covered && screen.name === 'vault' ? (
        <View testID="privacy-cover" style={styles.cover} />
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: color.canvas },
  dev: { padding: 16, alignItems: 'center' },
  devText: { color: color.inkMuted, fontSize: 13 },
  cover: { ...StyleSheet.absoluteFill, backgroundColor: color.canvas },
});
