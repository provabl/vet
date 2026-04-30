function toggleTheme() {
    const html = document.documentElement;
    const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    html.classList.add('theme-transitioning');
    html.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateThemeIcon(next);
    setTimeout(() => html.classList.remove('theme-transitioning'), 250);
}
function updateThemeIcon(theme) {
    const icon = document.getElementById('theme-icon');
    const btn  = document.getElementById('theme-toggle');
    if (!icon || !btn) return;
    icon.textContent = theme === 'dark' ? '☀️' : '🌙';
    btn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
}
document.addEventListener('DOMContentLoaded', function () {
    const themeBtn = document.getElementById('theme-toggle');
    if (themeBtn) { themeBtn.addEventListener('click', toggleTheme); updateThemeIcon(document.documentElement.getAttribute('data-theme') || 'light'); }
    const burger = document.getElementById('hamburger-btn');
    const links  = document.getElementById('nav-links');
    if (burger && links) {
        burger.addEventListener('click', () => { const open = links.classList.toggle('open'); burger.setAttribute('aria-expanded', String(open)); });
        links.querySelectorAll('a').forEach(a => a.addEventListener('click', () => { links.classList.remove('open'); burger.setAttribute('aria-expanded', 'false'); }));
    }
});
