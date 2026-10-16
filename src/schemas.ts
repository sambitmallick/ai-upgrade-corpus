import { z } from "zod";

export enum Plan {
  Free = "free",
  Pro = "pro",
  Team = "team",
}

/**
 * An IP address, v4 or v6.
 *
 * zod 4 split the old `z.string().ip()` into `z.ipv4()` / `z.ipv6()`, and its
 * IPv6 check is stricter than zod 3's: it rejects a scope/zone suffix such as
 * "fe80::1%eth0", which signups have always been allowed to send. Accept an
 * address-plus-zone as a third branch, validating the address half with the
 * real IPv6 check (and leaving the value untouched).
 */
const ipv6WithZone = z.string().refine(
  (value) => {
    const sep = value.indexOf("%");
    if (sep <= 0 || sep === value.length - 1) return false;
    return z.ipv6().safeParse(value.slice(0, sep)).success;
  },
  { error: "Invalid IPv6 address (with zone id)" }
);

const ipAddress = z.union([z.ipv4(), z.ipv6(), ipv6WithZone]);

/** A new account, as posted by the signup form. */
export const Signup = z.object({
  /**
   * zod 4's `z.uuid()` enforces the RFC 9562 version/variant bits; `z.guid()`
   * is the plain "8-4-4-4-12 hex" check that zod 3's `.uuid()` performed.
   */
  id: z.guid(),
  email: z.email(),
  name: z
    .string()
    .min(1)
    // zod 4 measures string length in Unicode code points, zod 3 in UTF-16 code
    // units -- emoji names land on either side of the 80 cap. Keep zod 3's rule.
    .refine((value) => value.length <= 80, {
      error: "String must contain at most 80 character(s)",
    }),
  age: z
    .number()
    .min(13)
    // zod 4's `.int()` means *safe* integer; zod 3's `.int()` was
    // Number.isInteger, which also accepts integers past MAX_SAFE_INTEGER.
    .refine((value) => Number.isInteger(value), {
      error: "Expected integer, received float",
    })
    .optional(),
  website: z.url().optional(),
  ip: ipAddress,
  plan: z.enum(Plan),
  /** feature flags, e.g. { beta: true } */
  flags: z.record(z.string(), z.boolean()),
  prefs: z
    .object({
      theme: z.enum(["light", "dark"]).default("light"),
      /** comes in as a string from the form; stored as a number */
      retries: z.string().transform(Number).prefault("3"),
    })
    // `prefault` (not `default`): the fallback is fed through the schema, so the
    // inner defaults still apply -- that is what zod 3's `.default({})` did.
    .prefault({}),
});
export type Signup = z.infer<typeof Signup>;

/** Service config, usually read from environment variables (so: strings). */
export const Config = z.object({
  port: z.string().transform(Number).prefault("8080"),
  hosts: z.array(ipAddress).min(1),
  timeoutMs: z.number().positive().default(5000),
});
export type Config = z.infer<typeof Config>;

/** A webhook handler: (event, payloadBytes) => void, checked at the boundary. */
export const Hook = z.function({
  input: [z.string(), z.number()],
  output: z.void(),
});
