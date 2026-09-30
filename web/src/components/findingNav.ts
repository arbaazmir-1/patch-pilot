// keyboard nav for finding lists: j/k move, enter opens evidence or follows a run row
export interface FindingNavOptions {
  escapeHref: string;
  keys?: Record<string, (nav: FindingNav) => void>;
}

export interface FindingNav {
  selectElement(el: HTMLElement): void;
}

export function setupFindingNav(options: FindingNavOptions): FindingNav {
  const items = Array.from(document.querySelectorAll<HTMLElement>('[data-finding], [data-nav-href]'));
  const cards = items.filter((el) => el.hasAttribute('data-finding'));
  const groups = Array.from(document.querySelectorAll<HTMLElement>('[data-group]'));
  const input = document.getElementById('ffilter') as HTMLInputElement | null;
  const empty = document.getElementById('ffilter-empty');
  let selected = -1;

  const visible = (): HTMLElement[] => items.filter((c) => !c.hidden);

  function select(index: number, scroll = true): void {
    const list = visible();
    items.forEach((c) => c.classList.remove('is-selected'));
    if (list.length === 0) {
      selected = -1;
      return;
    }
    selected = Math.max(0, Math.min(index, list.length - 1));
    const item = list[selected]!;
    item.classList.add('is-selected');
    if (scroll) item.scrollIntoView({ block: 'nearest' });
  }

  const nav: FindingNav = {
    selectElement(el) {
      const i = visible().indexOf(el);
      if (i >= 0) select(i);
    },
  };

  input?.addEventListener('input', () => {
    const q = input.value.trim().toLowerCase();
    for (const card of cards) card.hidden = !(card.dataset.search ?? '').includes(q);
    for (const group of groups) group.hidden = !group.querySelector('[data-finding]:not([hidden])');
    if (empty) empty.hidden = cards.some((c) => !c.hidden);
    selected = -1;
    items.forEach((c) => c.classList.remove('is-selected'));
  });

  items.forEach((item) => {
    item.addEventListener('click', (event) => {
      const href = item.dataset.navHref;
      if (href && !(event.target as HTMLElement).closest('a, button')) {
        window.location.href = href;
        return;
      }
      const i = visible().indexOf(item);
      if (i !== selected) select(i, false);
    });
  });

  document.addEventListener('keydown', (event) => {
    if (event.metaKey || event.ctrlKey || event.altKey) return;
    if (document.activeElement instanceof HTMLInputElement) {
      if (event.key === 'Escape') {
        if (input) {
          input.value = '';
          input.dispatchEvent(new Event('input'));
        }
        (document.activeElement as HTMLInputElement).blur();
      } else if (event.key === 'Enter' || event.key === 'ArrowDown') {
        event.preventDefault();
        (document.activeElement as HTMLInputElement).blur();
        select(0);
      }
      return;
    }
    const extra = options.keys?.[event.key];
    if (extra) {
      event.preventDefault();
      extra(nav);
      return;
    }
    switch (event.key) {
      case 'ArrowDown':
      case 'j':
        event.preventDefault();
        select(selected + 1);
        break;
      case 'ArrowUp':
      case 'k':
        event.preventDefault();
        select(selected <= 0 ? 0 : selected - 1);
        break;
      case 'Enter': {
        const focus = document.activeElement;
        if (focus instanceof HTMLAnchorElement || focus instanceof HTMLButtonElement || focus instanceof HTMLElement && focus.tagName === 'SUMMARY') break;
        const item = visible()[selected];
        if (!item) break;
        if (item.dataset.navHref) {
          event.preventDefault();
          window.location.href = item.dataset.navHref;
          break;
        }
        const details = item.querySelector('details');
        if (details) {
          event.preventDefault();
          details.open = !details.open;
        }
        break;
      }
      case '/':
        event.preventDefault();
        input?.focus();
        break;
      case 'Escape':
        window.location.href = options.escapeHref;
        break;
    }
  });

  return nav;
}
