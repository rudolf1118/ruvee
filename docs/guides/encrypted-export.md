# Encrypted export and restore

For people using Ruvee. Development build: use synthetic data only.

An **encrypted export** is a file with your vault, still encrypted, that you keep yourself. It
opens without the server and without any of your devices, but only with the **Recovery Key you
type when you make it**. It is not a backup of the server: it holds your items, not your account,
devices or logins. (Server backups are a separate, operator task: see
[backup-restore.md §3](../architecture/backup-restore.md#3-operational-server-backup-milestone-m1).)

## Make an export

1. Open **Security** and find **Encrypted export**.
2. Type a Recovery Key, then your master password, and choose **Download encrypted export**.
3. Keep the file, `ruvee-export-<date>.ruvee`, somewhere safe, **apart from your Recovery Kit**:
   whoever has both can read your vault as it was that day.

If you lose the Recovery Key you typed, the export can never be opened. Nothing on the server
helps.

## Look inside an export

On the welcome screen of any Ruvee web app (no account needed), choose **Open an encrypted
export**, pick the file and type its Recovery Key. You see the items as of the export's date.
Nothing is saved on that device, and closing the screen forgets everything.

## Restore an export into a new installation

Use this when the original server is gone, or to move to a new one.

1. On the new server's welcome screen, choose **Open an encrypted export**, pick the file and type
   its Recovery Key. Ruvee checks the whole file first; a damaged or altered file is refused and
   nothing is created.
2. Read the **restore preview**: the export's date, how many logins and notes will be imported,
   which stay in Trash, and how many deleted items (with no content) are left out.
3. Choose **Restore into a new account**. Create the account as usual, with the server's setup
   token, a new username and master password. You get a **new Recovery Kit**, which you must type
   back. The old kit and old password do not open the new account.
4. The import starts right after setup. When it finishes, Ruvee says **Import complete** with the
   number of items.

Everything is encrypted again with the new account's keys on your device before it is uploaded.
The export file, its Recovery Key and your items in readable form never leave your device. No
device, session or login of the original account is carried over.

## If the import is interrupted

- **Before the import starts** (while you look at the preview or create the account): nothing is
  imported. If you stopped after the account was created, it is simply empty; see below.
- **While it uploads** (connection lost, tab closed, browser restarted): unlock the new account
  in the same browser and it continues by itself. Items are never uploaded twice. Until it
  finishes, the vault says how many items are on the server, and you can't add or change items.
- **The account was created but the import never started** (for example the browser closed right
  after setup): unlock it, open **Security**, and use **Import an encrypted export**. This is
  offered only while the vault has never held an item.
- **This browser's data was cleared during the upload**: the account holds the items uploaded so
  far, and Ruvee will not import into a vault that already has items. Log in and recover the
  account with the new Recovery Kit, compare it with the export opened read-only, and add what is
  missing; or restore again into another fresh installation. Ruvee never deletes items for you.
