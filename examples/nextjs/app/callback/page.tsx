// The provider (mounted in layout.tsx) completes the OIDC code exchange; this page
// just renders, so it can stay a Server Component.
export default function CallbackPage() {
  return <p style={{ padding: 24 }}>Finishing sign in…</p>;
}
