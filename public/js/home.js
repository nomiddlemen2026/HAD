'use strict';
HAD.publicNav('/');
renderSearch(document.getElementById('search-root'));
document.querySelectorAll('[data-ico]').forEach(e => { e.innerHTML = HAD.icon(e.dataset.ico, 20); });
