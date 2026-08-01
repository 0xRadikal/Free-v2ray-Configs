/* Build shim.
 *
 * @radix-ui/primitive exposes "./is-development" only through the `development`
 * / `production` export conditions. Parcel's default resolver does not apply
 * those conditions, so the subpath fails to resolve and the whole build aborts
 * with: Failed to resolve '@radix-ui/primitive/is-development'.
 *
 * The upstream production build of that file is exactly `IS_DEVELOPMENT = false`
 * (verified by reading dist/internal/is-development.false.mjs), and this bundle
 * is a production build, so aliasing the subpath here is equivalent rather than
 * a workaround that changes behaviour.
 */
export const IS_DEVELOPMENT = false;
