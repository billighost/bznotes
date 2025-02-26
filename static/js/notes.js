// NeuralSearch class enhances the note search experience with smooth effects
class NeuralSearch {
    constructor() {
        this.searchInput = document.getElementById('searchInput');
        this.notesGrid = document.getElementById('notesGrid');
        this.notes = Array.from(this.notesGrid.querySelectorAll('.note-card'));
        this.init();
    }

    init() {
        this.searchInput.addEventListener('input', this.debounce(this.filterNotes.bind(this), 300));
        this.addQuantumEffects();
    }

    filterNotes() {
        const searchTerm = this.searchInput.value.toLowerCase();
        let hasMatches = false;

        this.notes.forEach(note => {
            const title = note.dataset.title.toLowerCase();
            const content = note.dataset.content.toLowerCase();
            const date = note.dataset.date.toLowerCase();

            const match = title.includes(searchTerm) || content.includes(searchTerm) || date.includes(searchTerm);

            this.toggleNoteVisibility(note, match);
            if (match) hasMatches = true;
        });

        this.toggleEmptyState(!hasMatches);
    }

    toggleNoteVisibility(note, show) {
        note.classList.toggle('quantum-hidden', !show);
        note.style.transform = show ? 'translateY(0) scale(1)' : 'translateY(50px) scale(0.95)';

        if (show) {
            const previewElem = note.querySelector('.note-preview');
            previewElem.innerHTML = this.highlightMatches(note.dataset.content, this.searchInput.value);
        }
    }

    highlightMatches(content, term) {
        if (!term) return content;
        const regex = new RegExp(`(${term})`, 'gi');
        return content.replace(regex, '<mark class="quantum-highlight">$1</mark>');
    }

    toggleEmptyState(show) {
        let emptyState = this.notesGrid.querySelector('.empty-state');
        if (show && !emptyState) {
            emptyState = this.createEmptyState();
            this.notesGrid.appendChild(emptyState);
        } else if (!show && emptyState) {
            emptyState.remove();
        }
    }

    createEmptyState() {
        const emptyDiv = document.createElement('div');
        emptyDiv.className = 'empty-state cosmic-pulse';
        emptyDiv.innerHTML = `
            <div class="quantum-flare"></div>
            <h3>No matches found</h3>
            <p>Try searching for different keywords.</p>
        `;
        return emptyDiv;
    }

    addQuantumEffects() {
        this.notes.forEach((note, index) => {
            note.style.transition = `all 0.6s ease-out ${index * 50}ms`;
        });
    }

    debounce(func, wait) {
        let timeout;
        return (...args) => {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }
}

// Initialize NeuralSearch when DOM content is loaded
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('notesGrid')) {
        new NeuralSearch();
    }
});
