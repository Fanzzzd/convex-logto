// The display-text rules both halves apply to user-chosen strings: the
// component when it stores them, the browser when it pre-checks a session
// label before the round-trip. Keep this module V8-safe, because the component
// imports it.

/** Longest accepted user-chosen session label, in code points. */
export const SESSION_LABEL_MAX_LENGTH = 64;

/**
 * Every invisible character class, not a hand-picked list of bidi overrides:
 * `Cc` controls, `Cf` format characters (the bidi embeddings and isolates, but
 * also RLM/LRM/ALM and the zero-width joiners `\s` never matches), and the line
 * and paragraph separators. The UI renders a label next to other sessions, and
 * any of these can make one entry impersonate another.
 */
const INVISIBLE_DISPLAY_CHARACTERS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

/** Emoji sequences join with ZWJ; dropping it would split families apart. */
const ZERO_WIDTH_JOINER = "\u200d";

/**
 * Collapse whitespace and drop invisible characters, so a label cannot smuggle
 * newlines or direction changes into a UI that lists it beside other sessions.
 */
export function normalizeDisplayText(raw: string): string {
  // Code points, not graphemes. The limit these feed is a storage bound, and
  // per-code-point filtering is what strips the invisible characters.
  return Array.from(raw)
    .filter(
      (character) =>
        character === ZERO_WIDTH_JOINER ||
        !INVISIBLE_DISPLAY_CHARACTERS.test(character),
    )
    .join("")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Would this label be rejected for its length? Exported so the browser half can
 * pre-empt the round-trip against *exactly* the rule the component applies:
 * normalization first, then a code-point count. Measuring the raw string
 * instead would reject a label the component would have accepted, because
 * normalization collapses whitespace and drops invisible characters.
 */
export function sessionLabelTooLong(raw: string): boolean {
  return (
    Array.from(normalizeDisplayText(raw)).length > SESSION_LABEL_MAX_LENGTH
  );
}
