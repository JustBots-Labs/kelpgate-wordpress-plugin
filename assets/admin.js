/**
 * Kelpgate settings page behaviour: auth-mode rows, connection test and incident log paging.
 * Values from PHP (AJAX URL, nonce, translated strings) arrive in the `kelpgateAdmin` object.
 */
(function () {
    'use strict';

    document.addEventListener('DOMContentLoaded', function () {
        var cfg = window.kelpgateAdmin || {};
        var i18n = cfg.i18n || {};

        var authMode = document.getElementById('kelpgate_auth_mode');
        function toggleAuthRows() {
            var isOAuth = authMode.value === 'oauth2';
            document.querySelectorAll('.kelpgate-row-oauth2').forEach(function (el) { el.style.display = isOAuth ? '' : 'none'; });
            document.querySelectorAll('.kelpgate-row-token').forEach(function (el) { el.style.display = isOAuth ? 'none' : ''; });
        }
        if (authMode) {
            authMode.addEventListener('change', toggleAuthRows);
            toggleAuthRows();
        }

        var btn = document.getElementById('kelpgate-test-btn');
        var icon = document.getElementById('kelpgate-test-icon');
        var banner = document.getElementById('kelpgate-banner');
        var bannerText = document.getElementById('kelpgate-banner-text');

        // Build the banner with text nodes only: the message can contain text returned by the
        // token/scan endpoints, which must never be interpreted as HTML.
        function setBanner(label, text) {
            bannerText.textContent = '';
            var strong = document.createElement('strong');
            strong.textContent = label;
            bannerText.appendChild(strong);
            bannerText.appendChild(document.createTextNode(String(text)));
        }

        if (btn) {
            btn.addEventListener('click', function () {
                btn.disabled = true;
                icon.classList.add('kelpgate-spinning');

                var data = new FormData();
                data.append('action', 'kelpgate_test_connection');
                data.append('security', cfg.nonce || '');

                fetch(cfg.ajaxUrl, {
                    method: 'POST',
                    body: data
                })
                .then(function (r) { return r.json(); })
                .then(function (json) {
                    btn.disabled = false;
                    icon.classList.remove('kelpgate-spinning');
                    banner.style.display = 'flex';

                    if (json.success && json.data && json.data.success) {
                        banner.className = 'kelpgate-banner healthy';
                        setBanner(i18n.connected, json.data.message);
                    } else {
                        var msg = (json.data && json.data.message) ? json.data.message : i18n.failed;
                        banner.className = 'kelpgate-banner error';
                        setBanner(i18n.error, msg);
                    }
                })
                .catch(function (err) {
                    btn.disabled = false;
                    icon.classList.remove('kelpgate-spinning');
                    banner.style.display = 'flex';
                    banner.className = 'kelpgate-banner error';
                    setBanner(i18n.networkError, err.message);
                });
            });
        }

        // Incident log pagination
        var incidentsBody = document.getElementById('kelpgate-incidents-body');
        if (incidentsBody) {
            var PAGE_SIZE = 10;
            var rows = Array.prototype.slice.call(incidentsBody.querySelectorAll('tr'));
            var totalRows = rows.length;
            var totalPages = Math.ceil(totalRows / PAGE_SIZE);
            var currentPage = 1;

            var updateIncidentPagination = function (page) {
                currentPage = page;
                var start = (page - 1) * PAGE_SIZE;
                var end = start + PAGE_SIZE;

                rows.forEach(function (row, idx) {
                    row.style.display = (idx >= start && idx < end) ? '' : 'none';
                });

                var infoEl = document.getElementById('kelpgate-page-info');
                if (infoEl && i18n.showing) {
                    infoEl.textContent = i18n.showing
                        .replace('%1$d', String(start + 1))
                        .replace('%2$d', String(Math.min(end, totalRows)))
                        .replace('%3$d', String(totalRows));
                }

                var prevBtn = document.getElementById('kelpgate-prev-btn');
                if (prevBtn) { prevBtn.disabled = (currentPage <= 1); }

                var nextBtn = document.getElementById('kelpgate-next-btn');
                if (nextBtn) { nextBtn.disabled = (currentPage >= totalPages); }

                var pageNums = document.getElementById('kelpgate-page-numbers');
                if (pageNums) {
                    pageNums.textContent = '';
                    for (var i = 1; i <= totalPages; i++) {
                        var pBtn = document.createElement('button');
                        pBtn.type = 'button';
                        pBtn.className = 'kelpgate-page-num' + (i === currentPage ? ' active' : '');
                        pBtn.textContent = String(i);
                        pBtn.setAttribute('data-page', String(i));
                        pBtn.addEventListener('click', function (e) {
                            updateIncidentPagination(parseInt(e.currentTarget.getAttribute('data-page'), 10));
                        });
                        pageNums.appendChild(pBtn);
                    }
                }
            };

            if (totalRows > PAGE_SIZE) {
                updateIncidentPagination(1);
                var prev = document.getElementById('kelpgate-prev-btn');
                if (prev) {
                    prev.addEventListener('click', function () {
                        if (currentPage > 1) { updateIncidentPagination(currentPage - 1); }
                    });
                }
                var next = document.getElementById('kelpgate-next-btn');
                if (next) {
                    next.addEventListener('click', function () {
                        if (currentPage < totalPages) { updateIncidentPagination(currentPage + 1); }
                    });
                }
            }
        }
    });
})();
