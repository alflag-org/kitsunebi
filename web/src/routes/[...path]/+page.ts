import { routeSurfaces } from '../../lib/navigation';

export const prerender = true;

export function entries() {
  return routeSurfaces.map(([path]) => ({ path }));
}

export function load({ params }: { params: { path?: string } }) {
  return { surface: params.path?.split('/')[0] ?? '' };
}
