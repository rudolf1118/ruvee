import type { ItemField, VaultItemView, VaultSummary } from '@/components/vault/types';

/**
 * SYNTHETIC DATA FOR THE DEVELOPMENT PREVIEW ONLY.
 *
 * Every person, company and address here is fictional. Domains use the
 * reserved `.example` TLD and phone numbers the fictional 555-01xx range.
 * No fixture contains a password, card number, security code or other
 * secret: concealed fields carry a fixed mask and nothing else.
 *
 * Only `app/preview/page.dev.tsx` may import this module. The production build
 * check fails if the marker below shows up in build output.
 */
export const FIXTURE_MARKER = 'ruvee-synthetic-preview-fixture';

const MASK = '••••••••••••';

export const previewVaults: VaultSummary[] = [
  { id: 'personal', name: 'Personal' },
  { id: 'household', name: 'Household' },
  { id: 'side', name: 'Side projects' },
];

interface LoginSeed {
  id: string;
  title: string;
  vaultId: string;
  username: string;
  website: string;
  notes?: string;
  tags: string[];
  edited: string;
  favorite?: boolean;
  trashed?: boolean;
}

function login(seed: LoginSeed): VaultItemView {
  const fields: ItemField[] = [
    { label: 'Username', display: seed.username },
    { label: 'Password', display: MASK, mono: true, concealed: true },
    { label: 'Website', display: seed.website },
  ];
  if (seed.notes) fields.push({ label: 'Notes', display: seed.notes, copyable: false });
  return {
    id: seed.id,
    kind: 'login',
    title: seed.title,
    subtitle: seed.username,
    vaultId: seed.vaultId,
    favorite: seed.favorite ?? false,
    trashed: seed.trashed ?? false,
    edited: seed.edited,
    tags: seed.tags,
    fields,
    searchText: [seed.username, seed.website],
  };
}

export const previewItems: VaultItemView[] = [
  login({
    id: 'i1',
    title: 'Lumen Mail',
    vaultId: 'personal',
    favorite: true,
    username: 'mara.ellison@lumenmail.example',
    website: 'lumenmail.example',
    notes: 'Main email. Kestrel Air and Orchard Grocery send receipts here.',
    tags: ['email', 'personal'],
    edited: 'Edited 2 days ago',
  }),
  login({
    id: 'i2',
    title: 'Cobalt Code',
    vaultId: 'personal',
    favorite: true,
    username: 'mara-dev',
    website: 'cobaltcode.example',
    tags: ['work', 'dev'],
    edited: 'Edited last week',
  }),
  login({
    id: 'i3',
    title: 'Fernbank Credit Union',
    vaultId: 'personal',
    username: 'mellison',
    website: 'fernbank.example',
    notes: 'Synthetic preview note.',
    tags: ['finance'],
    edited: 'Edited 8 months ago',
  }),
  login({
    id: 'i4',
    title: 'Kestrel Air',
    vaultId: 'personal',
    username: 'mara.ellison@lumenmail.example',
    website: 'kestrelair.example',
    tags: ['travel'],
    edited: 'Edited 8 months ago',
  }),
  login({
    id: 'i5',
    title: 'Mosaic Music',
    vaultId: 'personal',
    username: 'mara_e',
    website: 'mosaicmusic.example',
    tags: ['entertainment'],
    edited: 'Edited 1 year ago',
  }),
  login({
    id: 'i6',
    title: 'Orchard Grocery',
    vaultId: 'household',
    username: 'mara.ellison@lumenmail.example',
    website: 'orchardgrocery.example',
    notes: 'Delivery slot: Saturday mornings.',
    tags: ['household', 'shopping'],
    edited: 'Edited 3 weeks ago',
  }),
  login({
    id: 'i7',
    title: 'Brightline Energy',
    vaultId: 'household',
    username: 'customer-0001',
    website: 'brightline-energy.example',
    tags: ['household', 'utilities'],
    edited: 'Edited 3 weeks ago',
  }),
  login({
    id: 'i8',
    title: 'Tidepool Photos',
    vaultId: 'personal',
    username: 'mara.e',
    website: 'tidepool.example',
    tags: ['photos'],
    edited: 'Edited 2 months ago',
  }),
  login({
    id: 'i9',
    title: 'Parcelway',
    vaultId: 'household',
    username: 'mara.ellison@lumenmail.example',
    website: 'parcelway.example',
    tags: ['shopping'],
    edited: 'Edited 5 months ago',
  }),
  {
    id: 'i10',
    kind: 'note',
    title: 'Home Wi‑Fi',
    subtitle: 'Network: Larkspur-5G',
    vaultId: 'household',
    favorite: true,
    trashed: false,
    edited: 'Edited 1 month ago',
    tags: ['home'],
    fields: [
      {
        label: 'Note',
        display:
          'Network: Larkspur-5G\nRouter label: on the back of the router\n(Synthetic preview note.)',
      },
    ],
    searchText: [],
  },
  {
    id: 'i11',
    kind: 'note',
    title: 'Storage unit',
    subtitle: 'Unit 214 at Westgate Storage.',
    vaultId: 'personal',
    favorite: false,
    trashed: false,
    edited: 'Edited 4 months ago',
    tags: ['home'],
    fields: [
      {
        label: 'Note',
        display: 'Unit 214 at Westgate Storage.\nThe padlock key is in the kitchen drawer.',
      },
    ],
    searchText: [],
  },
  {
    id: 'i12',
    kind: 'card',
    title: 'Fernbank Debit',
    subtitle: '•••• 0000 · Expires 09/28',
    vaultId: 'personal',
    favorite: false,
    trashed: false,
    edited: 'Edited 6 months ago',
    tags: ['finance'],
    fields: [
      { label: 'Name on card', display: 'Mara J. Ellison' },
      { label: 'Card number', display: '•••• •••• •••• 0000', mono: true, concealed: true },
      { label: 'Expiry date', display: '09/28', mono: true },
      { label: 'Security code', display: '•••', mono: true, concealed: true },
    ],
    searchText: ['Mara J. Ellison'],
  },
  {
    id: 'i13',
    kind: 'card',
    title: 'Kestrel Rewards Card',
    subtitle: '•••• 0000 · Expires 03/27',
    vaultId: 'personal',
    favorite: false,
    trashed: false,
    edited: 'Edited 1 year ago',
    tags: ['travel', 'finance'],
    fields: [
      { label: 'Name on card', display: 'Mara J. Ellison' },
      { label: 'Card number', display: '•••• •••• •••• 0000', mono: true, concealed: true },
      { label: 'Expiry date', display: '03/27', mono: true },
      { label: 'Security code', display: '•••', mono: true, concealed: true },
    ],
    searchText: ['Mara J. Ellison'],
  },
  {
    id: 'i14',
    kind: 'identity',
    title: 'Mara Ellison',
    subtitle: 'mara.ellison@lumenmail.example',
    vaultId: 'personal',
    favorite: true,
    trashed: false,
    edited: 'Edited 3 months ago',
    tags: ['personal'],
    fields: [
      { label: 'Full name', display: 'Mara J. Ellison' },
      { label: 'Email', display: 'mara.ellison@lumenmail.example' },
      { label: 'Phone', display: '+1 (555) 014-2290' },
      { label: 'Address', display: '1180 Larkspur Lane, Apt 4B\nExampletown, ZZ 00000' },
    ],
    searchText: ['Mara J. Ellison', 'mara.ellison@lumenmail.example'],
  },
  login({
    id: 'i15',
    title: 'Quiet Forum (old account)',
    vaultId: 'personal',
    trashed: true,
    username: 'mara_e',
    website: 'quietforum.example',
    notes: 'No longer used.',
    tags: [],
    edited: 'Moved to Trash yesterday',
  }),
];
