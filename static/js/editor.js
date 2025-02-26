// editor.js
document.addEventListener('DOMContentLoaded', () => {
    // Font change functionality for editors
    const fontButton = document.getElementById('fontButton');
    const fontDropdown = document.getElementById('fontDropdown');
    if (fontButton && fontDropdown) {
        fontButton.addEventListener('click', () => {
            fontDropdown.classList.toggle('hidden');
        });

        fontDropdown.addEventListener('change', (e) => {
            const selectedFont = e.target.value;
            document.querySelectorAll('.quantum-editor, .neural-interface').forEach(editor => {
                editor.style.fontFamily = selectedFont;
            });
        });
    }

    // Calculator functionality (basic placeholder)
    const calcButton = document.getElementById('calcButton');
    const calcPanel = document.getElementById('calcPanel');
    if (calcButton && calcPanel) {
        calcButton.addEventListener('click', () => {
            calcPanel.classList.toggle('hidden');
        });
    }

    // Hover tooltip functionality for elements with a title attribute
    document.querySelectorAll('[title]').forEach(el => {
        el.addEventListener('mouseenter', () => {
            const tooltipText = el.getAttribute('title');
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            tooltip.innerText = tooltipText;
            document.body.appendChild(tooltip);
            const rect = el.getBoundingClientRect();
            tooltip.style.left = `${rect.left}px`;
            tooltip.style.top = `${rect.top - 30}px`;

            el.addEventListener('mouseleave', () => tooltip.remove());
        });
    });

    // Dark mode toggle for all editors
    const nightModeToggle = document.getElementById('nightModeBtn');
    if (nightModeToggle) {
        nightModeToggle.addEventListener('click', () => {
            document.body.classList.toggle('night-mode');
            localStorage.setItem('nightMode', document.body.classList.contains('night-mode'));
        });

        // Apply stored night mode on load
        if (localStorage.getItem('nightMode') === 'true') {
            document.body.classList.add('night-mode');
        }
    }
});
