import type { ReactNode } from 'react';
import {
  ActivityIndicator,
  KeyboardAvoidingView,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
  type TextInputProps,
} from 'react-native';
import { color, radius } from './theme';

export function Screen({ children, scroll = true }: { children: ReactNode; scroll?: boolean }) {
  return (
    <KeyboardAvoidingView style={styles.screen} behavior="height">
      {scroll ? (
        <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
          {children}
        </ScrollView>
      ) : (
        <View style={[styles.content, styles.fill]}>{children}</View>
      )}
    </KeyboardAvoidingView>
  );
}

export function Heading({ children }: { children: ReactNode }) {
  return (
    <Text style={styles.heading} accessibilityRole="header">
      {children}
    </Text>
  );
}

export function Body({ children, muted = false }: { children: ReactNode; muted?: boolean }) {
  return <Text style={[styles.body, muted && styles.muted]}>{children}</Text>;
}

export function Field({
  label,
  testID,
  ...input
}: { label: string; testID: string } & Omit<TextInputProps, 'style'>) {
  return (
    <View style={styles.field}>
      <Text style={styles.label}>{label}</Text>
      <TextInput
        testID={testID}
        accessibilityLabel={label}
        style={[styles.input, input.multiline && styles.multiline]}
        placeholderTextColor={color.inkMuted}
        autoCorrect={false}
        {...input}
      />
    </View>
  );
}

export function Button({
  title,
  onPress,
  testID,
  kind = 'primary',
  busy = false,
  disabled = false,
}: {
  title: string;
  onPress: () => void;
  testID: string;
  kind?: 'primary' | 'secondary' | 'danger';
  busy?: boolean;
  disabled?: boolean;
}) {
  const off = disabled || busy;
  return (
    <Pressable
      testID={testID}
      accessibilityRole="button"
      accessibilityState={{ disabled: off, busy }}
      disabled={off}
      onPress={onPress}
      style={({ pressed }) => [
        styles.button,
        kind === 'primary' && styles.primary,
        kind === 'secondary' && styles.secondary,
        kind === 'danger' && styles.dangerButton,
        (pressed || off) && styles.pressed,
      ]}
    >
      {busy ? (
        <ActivityIndicator color={kind === 'primary' ? 'white' : color.brand} />
      ) : (
        <Text
          style={[
            styles.buttonText,
            kind !== 'primary' && styles.secondaryText,
            kind === 'danger' && styles.dangerText,
          ]}
        >
          {title}
        </Text>
      )}
    </Pressable>
  );
}

export function Banner({
  children,
  tone = 'info',
  testID,
}: {
  children: ReactNode;
  tone?: 'info' | 'caution' | 'danger';
  testID?: string;
}) {
  return (
    <View
      accessibilityRole="alert"
      style={[
        styles.banner,
        tone === 'caution' && styles.caution,
        tone === 'danger' && styles.dangerBanner,
      ]}
    >
      {/* The test id is on the text, so tests can read the message. */}
      <Text
        testID={testID}
        style={[
          styles.bannerText,
          tone === 'danger' && styles.dangerText,
          tone === 'caution' && styles.cautionText,
        ]}
      >
        {children}
      </Text>
    </View>
  );
}

export const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: color.canvas },
  content: { padding: 20, paddingTop: 56, gap: 14 },
  fill: { flex: 1 },
  heading: { fontSize: 26, fontWeight: '700', color: color.ink },
  body: { fontSize: 16, lineHeight: 22, color: color.inkSecondary },
  muted: { color: color.inkMuted, fontSize: 14 },
  field: { gap: 6 },
  label: { fontSize: 14, fontWeight: '600', color: color.inkSecondary },
  input: {
    backgroundColor: color.surface,
    borderColor: color.lineInput,
    borderWidth: 1,
    borderRadius: radius.control,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 16,
    color: color.ink,
  },
  multiline: { minHeight: 110, textAlignVertical: 'top' },
  button: {
    borderRadius: radius.control,
    paddingVertical: 13,
    alignItems: 'center',
    justifyContent: 'center',
  },
  primary: { backgroundColor: color.brand },
  secondary: { backgroundColor: color.surface, borderWidth: 1, borderColor: color.line },
  dangerButton: { backgroundColor: color.surface, borderWidth: 1, borderColor: color.danger },
  pressed: { opacity: 0.6 },
  buttonText: { color: 'white', fontSize: 16, fontWeight: '600' },
  secondaryText: { color: color.brandText },
  dangerText: { color: color.danger },
  banner: {
    backgroundColor: color.brandWash,
    borderColor: color.brandLine,
    borderWidth: 1,
    borderRadius: radius.row,
    padding: 12,
  },
  caution: { backgroundColor: color.cautionWash, borderColor: color.cautionLine },
  dangerBanner: { backgroundColor: color.dangerWash, borderColor: color.danger },
  bannerText: { color: color.brandStrong, fontSize: 14, lineHeight: 20 },
  cautionText: { color: color.cautionStrong },
});
