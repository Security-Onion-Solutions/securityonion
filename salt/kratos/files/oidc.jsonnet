local claims = std.extVar('claims');
{
  identity: {
    traits: {
      email: if 'email' in claims then claims.email else claims.preferred_username
    },
  },
}