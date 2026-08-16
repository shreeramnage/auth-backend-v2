export function validate(schema) {
  return (req, res, next) => {
    // Run the request body through the schema without throwing
    const result = schema.safeParse(req.body);

    if (!result.success) {
      // Turn zod's list of problems into one readable message
      const message = result.error.issues.map((issue) => issue.message).join(', ');
      return res.status(400).json({ message });
    }

    // Replace req.body with the validated data — strips anything .strict() would reject anyway
    req.body = result.data;
    next();
  };
}
