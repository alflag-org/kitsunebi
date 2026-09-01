export const routeSurfaces = [
  ['services', 'Services'],
  ['service-detail', 'Service detail'],
  ['clusters', 'Clusters'],
  ['cluster-revisions', 'Cluster revisions'],
  ['execution-units', 'Execution units'],
  ['worlds', 'Worlds'],
  ['proxy-pools', 'Proxy pools'],
  ['proxy-instances', 'Proxy instances'],
  ['external-endpoints', 'External endpoints'],
  ['console', 'Console'],
  ['files', 'Files'],
  ['file-diff', 'File diff'],
  ['artifacts', 'Artifacts'],
  ['plugins-mods', 'Plugins / mods'],
  ['change-sessions', 'Change sessions'],
  ['operations', 'Operations'],
  ['backups-restore', 'Backups / restore'],
  ['access-policies', 'Access policies'],
  ['lifecycle-decisions', 'Lifecycle / decisions'],
  ['audit', 'Audit']
] as const;

export type Surface = (typeof routeSurfaces)[number][1] | 'Dashboard';

export function surfaceFromPath(path: string | undefined): Surface {
  const entry = routeSurfaces.find(([slug]) => slug === (path ?? '').split('/')[0]);
  return entry?.[1] ?? 'Dashboard';
}
