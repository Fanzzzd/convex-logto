// The provider in the layout finishes the code exchange under this page and
// replace-navigates away, so this can stay a Server Component that only renders.
export default function CallbackPage() {
  return <p style={{ padding: 24 }}>Finishing sign in…</p>;
}
