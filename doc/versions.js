// The version selector and the "not the latest release" banner of the
// published book. `doc/build_versions.py` injects this file into every version
// it builds, prefixed with a line setting `window.ACME_PROXY_DOC_VERSION` to
// that build's version (`0.6`, `dev`); a plain `mdbook build doc/` does not
// load it at all.
//
// The site is laid out as `/<X.Y>/` per minor line, `/dev/` for `main`, and a
// second copy of the latest release at the root, with `versions.json` beside
// them. Each copy works out the site root from its own location, so the same
// build serves both `/` and `/0.6/`.

(() => {
    const version = window.ACME_PROXY_DOC_VERSION;
    if (!version) {
        return;
    }

    // `path_to_root` is the top-level constant mdBook's page template defines.
    const bookRoot = new URL(path_to_root, window.location.href);
    const page = window.location.href.slice(bookRoot.href.length);
    const prefix = `/${version}/`;
    const siteRoot = bookRoot.pathname.endsWith(prefix)
        ? new URL('../', bookRoot)
        : bookRoot;

    const style = document.createElement('style');
    style.textContent = `
        .version-select {
            margin: auto 0.5rem;
            padding: 0.1rem 0.3rem;
            background: var(--bg);
            color: var(--fg);
            border: 1px solid var(--searchbar-border-color);
            border-radius: 3px;
            font-size: 1.4rem;
        }
        .version-banner {
            margin-bottom: 1.5rem;
            padding: 0.6rem 1rem;
            background: var(--quote-bg);
            border-left: 4px solid var(--links);
        }
    `;
    document.head.appendChild(style);

    // The same page in another version, or that version's front page when the
    // page does not exist there.
    const go = async (target) => {
        const root = new URL(target.path, siteRoot);
        const same = new URL(page, root);
        try {
            const response = await fetch(same, { method: 'HEAD' });
            window.location.href = response.ok ? same.href : root.href;
        } catch {
            window.location.href = root.href;
        }
    };

    const render = (versions) => {
        const latest = versions.find((v) => v.latest);
        const current = versions.find((v) => v.version === version);
        if (!latest || !current) {
            return;
        }

        const select = document.createElement('select');
        select.className = 'version-select';
        select.setAttribute('aria-label', 'Documentation version');
        for (const v of versions) {
            const option = document.createElement('option');
            option.value = v.version;
            option.textContent = v.latest ? `${v.tag} (latest)`
                : v.tag ? v.tag : 'main (unreleased)';
            option.selected = v.version === version;
            select.appendChild(option);
        }
        select.addEventListener('change', () => {
            const target = versions.find((v) => v.version === select.value);
            go(target);
        });
        const buttons = document.querySelector('#mdbook-menu-bar .right-buttons');
        if (buttons) {
            buttons.prepend(select);
        }

        if (current.latest) {
            return;
        }
        const banner = document.createElement('div');
        banner.className = 'version-banner';
        const what = current.tag
            ? `the ${current.tag} release, not the latest one`
            : 'the unreleased <code>main</code> branch';
        banner.innerHTML = `This page documents ${what}. `
            + `<a href="#">Read it for ${latest.tag}</a>.`;
        banner.querySelector('a').addEventListener('click', (event) => {
            event.preventDefault();
            go(latest);
        });
        const main = document.querySelector('#mdbook-content main');
        if (main) {
            main.prepend(banner);
        }
    };

    fetch(new URL('versions.json', siteRoot))
        .then((response) => (response.ok ? response.json() : []))
        .then(render)
        .catch(() => {});
})();
