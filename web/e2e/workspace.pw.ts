import { expect, test, type Page } from '@playwright/test';

const services = [
  { id: 's1', display_name: 'Survival', key: 'survival', current_cluster: 'c1', lifecycle: 'Active' },
  { id: 's2', display_name: 'Creative', key: 'creative', current_cluster: null, lifecycle: 'Maintenance' }
];
const units = [{ id: 'u1', name: 'Survival / main', service_id: 's1' }, { id: 'u2', name: 'Creative / build', service_id: 's2' }];

async function install(page: Page) {
  const records: Record<string, unknown> = {
    session: { csrf_token: 'test' },
    services,
    'services/s1': services[0],
    clusters: [{ id: 'c1', key: 'survival-main' }],
    'execution-units': units,
    'change-sessions': [
      { id: 'finished', state: 'Accepted' }, { id: 'working', state: 'Editing', target_cluster: 'c1' }
    ],
    'proxy-pools': [{ id: 'p1', key: 'edge', instances: ['a', 'b'] }]
  };
  await page.route('**/health', (route) => route.fulfill({ json: { status: 'healthy' } }));
  await page.route('**/api/v1/**', (route) => {
    const path = new URL(route.request().url()).pathname.slice('/api/v1/'.length);
    return route.fulfill(path in records ? { json: records[path] } : { status: 404, json: { error: 'missing' } });
  });
}

test('searches real service names and clusters, filters lifecycle and opens a reloadable detail', async ({ page }) => {
  await install(page);
  await page.goto('/');
  const directory = page.getByRole('region', { name: 'Service directory' });
  await expect(directory.getByRole('row')).toHaveCount(3);
  await expect(page.getByText('2 instances')).toBeVisible();
  await expect(page.getByText('Editing', { exact: true })).toBeVisible();
  await expect(page.getByText(/finished|accepted/i)).toHaveCount(0);
  await page.getByRole('button', { name: 'Maintenance 1' }).click();
  await expect(directory.getByRole('row')).toHaveCount(2);
  await expect(directory.getByRole('link', { name: /Creative/ })).toBeVisible();
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await page.getByRole('searchbox').fill('survival-main');
  await expect(directory.getByRole('row')).toHaveCount(2);
  await directory.getByRole('link', { name: /Survival/ }).click();
  await expect(page).toHaveURL(/\/service-detail\?id=s1$/);
  await page.reload();
  await expect(page.getByRole('heading', { level: 1, name: 'Survival' })).toBeVisible();
  await page.getByRole('link', { name: 'View execution units' }).click();
  await expect(page.getByRole('button', { name: units[0].name })).toBeVisible();
  await expect(page.getByRole('button', { name: units[1].name })).toHaveCount(0);
  await page.goBack();
  await expect(page.getByRole('heading', { level: 1, name: 'Survival' })).toBeVisible();
  await page.goBack();
  await expect(page.getByRole('heading', { name: 'Service overview' })).toBeVisible();
});

test('keeps services readable when clusters are unavailable', async ({ page }) => {
  await install(page);
  await page.route('**/api/v1/clusters', (route) => route.fulfill({ status: 403, json: { error: 'Forbidden' } }));
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText('Cluster names unavailable');
  await expect(page.getByRole('row', { name: /Survival/ })).toContainText('Name unavailable');
  await expect(page.getByRole('row', { name: /Creative/ })).toContainText('Unassigned');
});

test('reviews only the selected execution unit and discards confirmation on target change', async ({ page }) => {
  await install(page);
  const reviewed: string[] = [];
  await page.route('**/lifecycle/prepare', (route) => {
    reviewed.push(new URL(route.request().url()).pathname);
    return route.fulfill({ json: {
      session_id: 'change', plan_id: 'plan', plan_hash: 'hash', expires_at: Math.floor(Date.now() / 1000) + 300,
      target_name: units[1].name, running: true, action: 'restart', impact: 'Connected players will be disconnected.'
    } });
  });
  await page.goto('/execution-units');
  await page.getByRole('button', { name: units[1].name }).click();
  await expect(page.getByLabel('Target', { exact: true })).toHaveValue('u2');
  await page.getByRole('button', { name: 'Review operation' }).click();
  await expect(page.getByRole('button', { name: 'Confirm restart' })).toBeEnabled();
  await page.getByRole('button', { name: units[0].name }).click();
  await expect(page.getByLabel('Target', { exact: true })).toHaveValue('u1');
  await expect(page.getByRole('button', { name: 'Confirm restart' })).toHaveCount(0);
  expect(reviewed).toEqual(['/api/v1/execution-units/u2/lifecycle/prepare']);
});

test('navigates the mobile workspace by keyboard without horizontal overflow', async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 780 });
  await install(page);
  await page.goto('/');
  await expect(page.getByRole('link', { name: /Survival/ })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  const menu = page.getByRole('button', { name: 'Open navigation' });
  await menu.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(menu).toBeFocused();
  await menu.click();
  await page.getByRole('link', { name: 'Files', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page).toHaveURL(/\/files$/);
  await expect(page.getByRole('combobox', { name: 'Execution Unit' })).toHaveValue('u1');
});
