import { useLogtoAuth } from "convex-logto/react";

export function SignInPage() {
  const { signIn } = useLogtoAuth();
  return (
    <section>
      <h1>Sign in</h1>
      <button onClick={() => void signIn()}>Sign in with Logto</button>
    </section>
  );
}
