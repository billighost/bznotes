class CosmicUI {
    constructor() {
        this.initParticles();
        this.initNightMode();
        this.initAIModule();
    }

    initParticles() {
        const container = document.createElement('div');
        container.classList.add('cosmic-particles-container');
        document.body.appendChild(container);

        for (let i = 0; i < 100; i++) {
            const star = document.createElement('div');
            star.classList.add('star');
            star.style.width = `${Math.random() * 2 + 1}px`;
            star.style.height = star.style.width;
            star.style.left = `${Math.random() * 100}%`;
            star.style.top = `${Math.random() * 100}%`;
            container.appendChild(star);
        }

        setInterval(() => {
            if (document.body.classList.contains('night-mode')) {
                for (let i = 0; i < 5; i++) {
                    this.createShootingStar(container);
                }
            }
        }, 2000);
    }

    createShootingStar(container) {
        const shootingStar = document.createElement('div');
        shootingStar.classList.add('shooting-star');
        const screenWidth = window.innerWidth;
        const screenHeight = window.innerHeight;

        let startX, startY, deltaX, deltaY;

        if (Math.random() < 0.5) {
            startX = 0;
            startY = Math.random() * screenHeight;
            deltaX = screenWidth;
            deltaY = (Math.random() - 0.5) * screenHeight;
        } else {
            startX = Math.random() * screenWidth;
            startY = 0;
            deltaX = (Math.random() - 0.5) * screenWidth;
            deltaY = screenHeight;
        }

        shootingStar.style.left = `${startX}px`;
        shootingStar.style.top = `${startY}px`;
        shootingStar.style.opacity = '1';

        container.appendChild(shootingStar);

        setTimeout(() => {
            shootingStar.style.transition = 'transform 2s linear, opacity 2s linear';
            shootingStar.style.transform = `translate(${deltaX}px, ${deltaY}px) scale(0.5)`;
            shootingStar.style.opacity = '0';
        }, 50);

        setTimeout(() => shootingStar.remove(), 2000);
    }

    initNightMode() {
        const nightModeBtn = document.getElementById('nightModeBtn');
        if (nightModeBtn) {
            if (localStorage.getItem('nightMode') === 'true') {
                document.body.classList.add('night-mode');
            }

            nightModeBtn.addEventListener('click', () => {
                document.body.classList.toggle('night-mode');
                localStorage.setItem('nightMode', document.body.classList.contains('night-mode'));
            });
        }
    }

    initAIModule() {
        const aiBtn = document.getElementById('aiToggleBtn');
        if (aiBtn) {
            aiBtn.addEventListener('click', () => this.toggleAI());
        }
    }

    toggleAI() {
        let aiPanel = document.getElementById('aiPanel');
        if (!aiPanel) {
            aiPanel = document.createElement('div');
            aiPanel.id = 'aiPanel';
            aiPanel.innerHTML = `<h3>🧠 Neural Assistant</h3><p>How can I help you today?</p>`;
            document.body.appendChild(aiPanel);
        } else {
            aiPanel.classList.toggle('hidden');
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new CosmicUI();
});
var socket = io.connect(location.protocol + '//' + document.domain + ':' + location.port + '/notifications');

// Real-Time Notification Handling
socket.on('notify_{{ current_user.id }}', function(message) {
    addNotification(message);
    updateNotificationCount(1);
});

// Toggle Notification Dropdown
function toggleNotifications() {
    const dropdown = document.getElementById('notification-dropdown');
    dropdown.classList.toggle('show');
    fetchNotifications();
}

// Fetch Notifications from the Server
function fetchNotifications() {
    fetch("{{ url_for('get_notifications') }}")
        .then(response => response.json())
        .then(data => {
            const list = document.getElementById("notification-list");
            list.innerHTML = "";
            data.notifications.forEach(notification => {
                const item = document.createElement("li");
                item.className = `notification-item ${notification.is_read ? '' : 'unread'}`;
                item.innerHTML = `<a href="/view_notification/${notification.id}">${notification.message}</a>`;
                list.appendChild(item);
            });
            updateNotificationCount(data.unread_count);
        });
}

// Add a New Notification to the List
function addNotification(message) {
    const list = document.getElementById("notification-list");
    const item = document.createElement("li");
    item.className = "notification-item unread";
    item.innerHTML = `<a href="/view_notification/${message.id}">${message.text}</a>`;
    list.prepend(item);
}

// Update Notification Count
function updateNotificationCount(count) {
    const badge = document.getElementById("notification-count");
    badge.textContent = count;
    badge.style.display = count > 0 ? "inline-block" : "none";
}
