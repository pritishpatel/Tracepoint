import type { NextAuthOptions } from "next-auth";

export const authOptions: NextAuthOptions = {
  providers: [
    {
      id: "oidc",
      name: "Enterprise SSO",
      type: "oauth",
      wellKnown: process.env.OIDC_ISSUER
        ? `${process.env.OIDC_ISSUER}/.well-known/openid-configuration`
        : undefined,
      clientId: process.env.OIDC_CLIENT_ID,
      clientSecret: process.env.OIDC_CLIENT_SECRET,
      authorization: { params: { scope: "openid email profile" } },
      idToken: true,
      checks: ["pkce", "state"],
      profile(profile) {
        return {
          id: profile.sub,
          name: profile.name ?? profile.preferred_username ?? profile.email,
          email: profile.email,
          image: null,
        };
      },
    },
  ],
  session: {
    strategy: "jwt",
  },
  callbacks: {
    jwt({ token, account, profile }) {
      if (account?.access_token) {
        token.accessToken = account.access_token;
      }
      if (profile && "realm_access" in profile) {
        const realmAccess = profile.realm_access as { roles?: string[] };
        token.roles = realmAccess.roles ?? [];
      }
      return token;
    },
    session({ session, token }) {
      session.accessToken = token.accessToken as string | undefined;
      session.roles = (token.roles as string[] | undefined) ?? [];
      return session;
    },
  },
};
