# Moving an account from before device keys

For people using Ruvee. Development build: use synthetic data only. This applies only to an
account created **before device keys (D-31)**. An account created since then never needs it.

## Why the account has to move

Since D-31, the server checks every change of account keys against an account verification key
(`AVPK`) that only the account's own key can match. An older account has none, and the server
can't safely take one on trust: someone who has only your Recovery Kit's auth value could
otherwise register their own. So such an account is never given one, by any path
([device-proof.md §9](../security/device-proof.md#9-accounts-from-before-d-31-synthetic-data-only)).
It can't sync, its devices can't be enrolled again, the Recovery Kit is refused for it, and a
restored server holding it can't be reopened. It also never becomes eligible for real data.

Nothing is deleted. Each browser that held the vault keeps its local copy and opens it offline
with the master password. The way forward is a **new account**, on a **new installation** (V1 has
one account per server), filled from an encrypted export.

## What you can tell from the app

After unlocking, the app says the account was created before device keys and can no longer sync,
and **Security → Move to a new account** appears. Choosing **Use your Recovery Kit** for this
account says the same and changes nothing.

## Steps

Do them in this order. Don't erase anything until step 6.

1. **Open the old vault on a browser that has it.** Unlock with the master password. It works
   offline. Use the browser with the newest changes; if several browsers hold changes, repeat
   steps 2 and 3 on each.
2. **Download the verified copy.** In **Security → Move to a new account**, type the account's
   current Recovery Key and the master password, and choose **Download verified copy**. The file
   (`ruvee-export-<date>-verified.ruvee`) holds the last state of the vault that this browser
   verified with the server, encrypted under that Recovery Key. It is made on the device and never
   uploaded.
3. **Note what the file can't hold.** The same screen lists, by title, every change waiting to sync
   (new, edited or deleted) and every unresolved conflict. Those were never verified, so no export
   format holds them. The download asks you to acknowledge them first. Keep the list: **the move
   is not complete until each item on it is copied by hand** (step 5).
4. **Set up the new account.** On a new installation, in a browser profile with no Ruvee data,
   open the web app, choose **Open an encrypted export**, pick the file and type the old Recovery
   Key, check the preview, then **Restore into a new account**. Setup asks for the installation's
   setup token, a username and a master password, and makes a new Recovery Kit: this is the normal
   D-31 setup, which registers the new device key and the new `AVPK`. The import then re-encrypts
   every item under the new account's keys and uploads it.
5. **Copy the listed changes by hand.** On the old browser, open each listed item (it is in the
   item list, marked as waiting to sync or in conflict) and add, change or delete it in the new
   account. For a conflict, the item shows the other device's version, and its banner names this
   device's version. To see all of this device's version, choose **Keep this device's version**:
   it works offline, the draft becomes a change waiting to sync (still listed, as edited), and
   the item then shows it in full.
6. **Check the new account before retiring anything.** Lock and unlock it, check that every item
   is there and that it syncs, and add a second device if you use one. Its Recovery Kit was
   checked during setup, when you typed it back; store it apart from the export file. (A recovery
   with it on a spare browser also works, but replaces the kit and ends the other sessions.) Only
   then stop using the old installation. Ruvee never erases the old browser by itself, and the
   move screen has no erase button. Removing that copy later is up to you (the browser's
   site-data settings).

## Limits

- The export holds items as last verified. Pending edits and conflict drafts move only by hand.
- Item history, devices, sessions and the activity log stay with the old account.
- The old Recovery Kit opens the export file: keep the file and the kit apart, and destroy the
  file when the move is checked.
- A browser that never synced since it was set up or recovered has no verified copy: the export
  is refused and only copying by hand remains.
- None of this is a security review. Real data still waits for the independent review (D-19).
