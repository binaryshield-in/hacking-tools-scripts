// Search functionality
const searchInput = document.getElementById('searchInput');
const toolsGrid = document.getElementById('toolsGrid');
const noResults = document.getElementById('noResults');
const toolBoxes = document.querySelectorAll('.tool-box');

searchInput.addEventListener('input', function() {
    const searchTerm = this.value.toLowerCase().trim();
    let visibleCount = 0;

    toolBoxes.forEach(box => {
        const title = box.getAttribute('data-title').toLowerCase();
        
        if (title.includes(searchTerm)) {
            box.style.display = 'block';
            visibleCount++;
        } else {
            box.style.display = 'none';
        }
    });

    if (visibleCount === 0) {
        toolsGrid.style.display = 'none';
        noResults.style.display = 'block';
    } else {
        toolsGrid.style.display = 'grid';
        noResults.style.display = 'none';
    }
});
