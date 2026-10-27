import { useCallback, useState } from 'react';
import { FlatList, Pressable, StyleSheet, Text, View } from 'react-native';
import type { CompatResult } from './checks';

/**
 * Development-only screen that runs the Stage 1 compatibility checks on the device and shows
 * each result as it arrives. The summary line is also logged with a fixed prefix so the test
 * harness can collect it from logcat; it contains ids, timings and error names only.
 */
export function CompatScreen({ onClose }: { onClose: () => void }) {
  const [results, setResults] = useState<CompatResult[]>([]);
  const [state, setState] = useState<'idle' | 'running' | 'done'>('idle');

  const run = useCallback(() => {
    setResults([]);
    setState('running');
    // Loaded on demand so the checks (and libsodium.js) are evaluated only when asked for.
    const { runCompatChecks } = require('./checks') as typeof import('./checks');
    void runCompatChecks((r) => {
      setResults((prev) => [...prev, r]);
    }).then((all) => {
      const failed = all.filter((r) => !r.ok).length;
      console.log(
        `RUVEE_COMPAT_SUMMARY ${JSON.stringify({ total: all.length, failed, results: all })}`,
      );
      setState('done');
    });
  }, []);

  const failed = results.filter((r) => !r.ok).length;
  return (
    <View style={styles.root}>
      <View style={styles.header}>
        <Text style={styles.title} accessibilityRole="header">
          Native compatibility
        </Text>
        <Pressable testID="compat-close" onPress={onClose} accessibilityRole="button">
          <Text style={styles.link}>Close</Text>
        </Pressable>
      </View>
      <Pressable
        testID="compat-run"
        style={[styles.button, state === 'running' && styles.buttonDisabled]}
        disabled={state === 'running'}
        onPress={run}
        accessibilityRole="button"
      >
        <Text style={styles.buttonText}>{state === 'running' ? 'Running…' : 'Run checks'}</Text>
      </Pressable>
      <Text testID="compat-status" style={styles.status}>
        {state === 'done'
          ? `Done: ${results.length} checks, ${failed} failed`
          : state === 'running'
            ? `${results.length} checks so far`
            : 'Synthetic inputs only.'}
      </Text>
      <FlatList
        data={results}
        keyExtractor={(r) => `${r.group}/${r.id}`}
        renderItem={({ item }) => (
          <View style={styles.row}>
            <Text style={[styles.badge, item.ok ? styles.ok : styles.fail]}>
              {item.ok ? 'PASS' : 'FAIL'}
            </Text>
            <View style={styles.rowBody}>
              <Text style={styles.rowTitle}>
                {item.group} · {item.id} · {item.ms} ms
              </Text>
              {item.detail ? <Text style={styles.rowDetail}>{item.detail}</Text> : null}
              {item.error ? <Text style={styles.rowError}>{item.error}</Text> : null}
            </View>
          </View>
        )}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, padding: 16, backgroundColor: '#0f1115' },
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  title: { color: '#f2f3f5', fontSize: 20, fontWeight: '600' },
  link: { color: '#8ab4ff', fontSize: 16 },
  button: { marginTop: 16, backgroundColor: '#3b6cf6', borderRadius: 8, padding: 12 },
  buttonDisabled: { opacity: 0.5 },
  buttonText: { color: 'white', textAlign: 'center', fontWeight: '600' },
  status: { color: '#c9ccd3', marginVertical: 12 },
  row: { flexDirection: 'row', paddingVertical: 6, gap: 8 },
  badge: { width: 44, fontWeight: '700', fontSize: 12 },
  ok: { color: '#4ade80' },
  fail: { color: '#f87171' },
  rowBody: { flex: 1 },
  rowTitle: { color: '#e5e7eb', fontSize: 13 },
  rowDetail: { color: '#9ca3af', fontSize: 12 },
  rowError: { color: '#fca5a5', fontSize: 12 },
});
