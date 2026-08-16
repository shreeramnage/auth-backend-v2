import z from "zod";

export const postSchema = z.object({
  title: z.string().min(1),
  body: z.string().min(1),
}).strict();
