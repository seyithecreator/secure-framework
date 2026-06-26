document.addEventListener('DOMContentLoaded', function () {
    var toggle = document.getElementById('sfMenuToggle');
    var links  = document.getElementById('sfNavLinks');
    if (toggle && links) {
        toggle.addEventListener('click', function () {
            links.classList.toggle('open');
            toggle.classList.toggle('open');
        });
        // Close menu when a link is clicked
        links.querySelectorAll('a').forEach(function (a) {
            a.addEventListener('click', function () {
                links.classList.remove('open');
                toggle.classList.remove('open');
            });
        });
    }

    if (typeof lucide !== 'undefined') lucide.createIcons();
});
