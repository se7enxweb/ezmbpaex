/*
 * The admin node view of ezmbpaex (override node/view/full_caching_disabled.tpl) without inline code: the class icon
 * of the title opens the class menu, as its onclick attribute did, from data attributes:
 *   data-mbpaex-menu-open="ClassMenu"          the menu
 *   data-mbpaex-menu-values='{"%classID%":..}' the values (JSON)
 *   data-mbpaex-menu-languages='[...]'         %languages% (JSON)
 *   data-mbpaex-menu-title="Folder"            the header text
 *   data-mbpaex-menu-disable='[...]'           the submenu items to disable (JSON: a list, one id, or -1)
 *   data-mbpaex-menu-disable-item='"..."'      the item to disable (JSON: an id, or -1)
 * It calls the admin's ezpopmenu_showTopLevel() and ez_createAArray() (design/admin/javascript/popupmenu), so it works
 * with every admin design. Sets itself up once.
 */
(function () {
    if (window.ezmbpaexAdmin) {
        return;
    }
    window.ezmbpaexAdmin = true;

    function json(el, name, fallback) {
        try {
            var v = el.getAttribute(name);
            return v === null || v === '' ? fallback : JSON.parse(v);
        } catch (e) {
            return fallback;
        }
    }

    document.addEventListener('click', function (event) {
        var el = event.target && event.target.closest ? event.target.closest('[data-mbpaex-menu-open]') : null;
        if (!el || typeof window.ezpopmenu_showTopLevel !== 'function' || typeof window.ez_createAArray !== 'function') {
            return;
        }
        event.preventDefault();
        var values = json(el, 'data-mbpaex-menu-values', {}), flat = [];
        for (var key in values) {
            if (Object.prototype.hasOwnProperty.call(values, key)) {
                flat.push(key, values[key]);
            }
        }
        flat.push('%languages%', json(el, 'data-mbpaex-menu-languages', []));
        window.ezpopmenu_showTopLevel(event, el.getAttribute('data-mbpaex-menu-open'), window.ez_createAArray(flat),
                                      el.getAttribute('data-mbpaex-menu-title') || '',
                                      json(el, 'data-mbpaex-menu-disable', -1), json(el, 'data-mbpaex-menu-disable-item', -1));
    });
})();
