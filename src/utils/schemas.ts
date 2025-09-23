export const userSchema = {
  $id: 'https://example.com/schemas/user.json',
  type: 'object',
  additionalProperties: true,
  required: ['id', 'email', 'first_name', 'last_name', 'avatar'],
  properties: {
    id: { anyOf: [{ type: 'integer' }, { type: 'string' }] },
    email: { type: 'string', format: 'email' },
    first_name: { type: 'string' },
    last_name: { type: 'string' },
    avatar: { type: 'string', format: 'uri' },
  },
} as const;


