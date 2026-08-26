/**
 * P3c2-5 (Phase 3c-2): one definition of the audit page size.
 *
 * Three files carried this number independently before this phase - this
 * app's own /api/audit route handler, lib/api.ts's fetchAudit default, and
 * the audit page's own fetchAudit(200) call site. Three literals that had
 * to agree, with nothing making them agree.
 *
 * The value is deliberately unchanged. Showing a compliance operator fewer
 * rows on one screen is a product decision, not a performance fix, and
 * since Phase 3c-2 the page defers verification (D29) so the page size no
 * longer governs a per-record scan cost at all - the reason to lower it
 * went away in the same change that made it easy to.
 */
export const AUDIT_PAGE_SIZE = 200;
