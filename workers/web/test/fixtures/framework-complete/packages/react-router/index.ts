export function createFileRoute(path: string) {
  return (options: { component?: () => unknown }) => ({ path, ...options });
}
