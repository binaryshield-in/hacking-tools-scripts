// ========================================
// BinaryShield - Tools & Scripts JavaScript
// Features: Search, Pagination, Dynamic Tool Loading
// ========================================

// Configuration
const ITEMS_PER_PAGE = 12;
let currentPage = 1;
let filteredTools = [];
let allTools = [];

// DOM Elements
const searchInput = document.getElementById('searchInput');
const toolsGrid = document.getElementById('toolsGrid');
const noResults = document.getElementById('noResults');

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeTools();
    createPaginationControls();
    setupSearchListener();
    displayPage(currentPage);
});

// Initialize all tools from the DOM
function initializeTools() {
    const toolBoxes = document.querySelectorAll('.tool-box');
    allTools = Array.from(toolBoxes).map(box => ({
        element: box,
        title: box.getAttribute('data-title').toLowerCase(),
        html: box.outerHTML
    }));
    filteredTools = [...allTools];
}

// Create pagination controls
function createPaginationControls() {
    const paginationContainer = document.createElement('div');
    paginationContainer.id = 'pagination';
    paginationContainer.className = 'pagination-container';
    
    // Insert after tools grid
    toolsGrid.parentNode.insertBefore(paginationContainer, noResults);
}

// Display specific page
function displayPage(pageNumber) {
    currentPage = pageNumber;
    
    const startIndex = (pageNumber - 1) * ITEMS_PER_PAGE;
    const endIndex = startIndex + ITEMS_PER_PAGE;
    const pageTools = filteredTools.slice(startIndex, endIndex);
    
    // Clear grid
    toolsGrid.innerHTML = '';
    
    // Add tools for current page
    if (pageTools.length > 0) {
        pageTools.forEach(tool => {
            toolsGrid.innerHTML += tool.html;
        });
        toolsGrid.style.display = 'grid';
        noResults.style.display = 'none';
    } else {
        toolsGrid.style.display = 'none';
        noResults.style.display = 'block';
    }
    
    // Update pagination
    updatePagination();
    
    // Scroll to top smoothly
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Update pagination buttons
function updatePagination() {
    const totalPages = Math.ceil(filteredTools.length / ITEMS_PER_PAGE);
    const paginationContainer = document.getElementById('pagination');
    
    if (totalPages <= 1) {
        paginationContainer.style.display = 'none';
        return;
    }
    
    paginationContainer.style.display = 'flex';
    paginationContainer.innerHTML = '';
    
    // Previous button
    const prevBtn = createPaginationButton('← Previous', currentPage > 1, () => {
        if (currentPage > 1) displayPage(currentPage - 1);
    });
    paginationContainer.appendChild(prevBtn);
    
    // Page numbers
    const pageNumbersContainer = document.createElement('div');
    pageNumbersContainer.className = 'page-numbers';
    
    // Calculate page range to show
    let startPage = Math.max(1, currentPage - 2);
    let endPage = Math.min(totalPages, currentPage + 2);
    
    // Adjust range if at start or end
    if (currentPage <= 3) {
        endPage = Math.min(5, totalPages);
    }
    if (currentPage >= totalPages - 2) {
        startPage = Math.max(1, totalPages - 4);
    }
    
    // First page
    if (startPage > 1) {
        pageNumbersContainer.appendChild(createPageNumberButton(1, false));
        if (startPage > 2) {
            pageNumbersContainer.appendChild(createEllipsis());
        }
    }
    
    // Page numbers in range
    for (let i = startPage; i <= endPage; i++) {
        pageNumbersContainer.appendChild(createPageNumberButton(i, i === currentPage));
    }
    
    // Last page
    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            pageNumbersContainer.appendChild(createEllipsis());
        }
        pageNumbersContainer.appendChild(createPageNumberButton(totalPages, false));
    }
    
    paginationContainer.appendChild(pageNumbersContainer);
    
    // Next button
    const nextBtn = createPaginationButton('Next →', currentPage < totalPages, () => {
        if (currentPage < totalPages) displayPage(currentPage + 1);
    });
    paginationContainer.appendChild(nextBtn);
    
    // Page info removed per request (no "Page X of Y" display)
}

// Create pagination button
function createPaginationButton(text, enabled, onClick) {
    const button = document.createElement('button');
    button.className = 'pagination-btn';
    button.textContent = text;
    button.disabled = !enabled;
    if (enabled) {
        button.addEventListener('click', onClick);
    }
    return button;
}

// Create page number button
function createPageNumberButton(pageNumber, isActive) {
    const button = document.createElement('button');
    button.className = `page-number ${isActive ? 'active' : ''}`;
    button.textContent = pageNumber;
    if (!isActive) {
        button.addEventListener('click', () => displayPage(pageNumber));
    }
    return button;
}

// Create ellipsis
function createEllipsis() {
    const span = document.createElement('span');
    span.className = 'page-ellipsis';
    span.textContent = '...';
    return span;
}

// Setup search listener
function setupSearchListener() {
    let searchTimeout;
    
    searchInput.addEventListener('input', function() {
        // Debounce search
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            performSearch(this.value);
        }, 300);
    });
}

// Perform search
function performSearch(searchTerm) {
    const term = searchTerm.toLowerCase().trim();
    
    if (term === '') {
        // Show all tools
        filteredTools = [...allTools];
    } else {
        // Filter tools
        filteredTools = allTools.filter(tool => tool.title.includes(term));
    }
    
    // Reset to first page and display
    currentPage = 1;
    displayPage(1);
}

// Add CSS for pagination (inject into page)
const paginationStyles = document.createElement('style');
paginationStyles.textContent = `
    .pagination-container {
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 10px;
        margin: 40px 0;
        flex-wrap: wrap;
        padding: 20px;
    }

    .pagination-btn {
        padding: 10px 20px;
        background-color: #2e2e2e;
        color: #ffffff;
        border: 2px solid #ff0000;
        border-radius: 8px;
        font-family: 'Poppins', Arial, sans-serif;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
    }

    .pagination-btn:hover:not(:disabled) {
        background-color: #ff0000;
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(255, 0, 0, 0.4);
    }

    .pagination-btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
        border-color: #555;
    }

    .page-numbers {
        display: flex;
        gap: 5px;
        align-items: center;
    }

    .page-number {
        padding: 8px 14px;
        background-color: #2e2e2e;
        color: #00ff88;
        border: 2px solid #00ff88;
        border-radius: 8px;
        font-family: 'Poppins', Arial, sans-serif;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
        min-width: 40px;
    }

    .page-number:hover {
        background-color: #00ff88;
        color: #000000;
        transform: scale(1.1);
    }

    .page-number.active {
        background-color: #ff0000;
        color: #ffffff;
        border-color: #ff0000;
        cursor: default;
        transform: scale(1.15);
    }

    .page-ellipsis {
        color: #00ff88;
        padding: 0 5px;
        font-weight: bold;
    }

    // .page-info {
    //     color: #00ff88;
    //     font-size: 14px;
    //     font-weight: 600;
    //     margin-left: 15px;
    //     padding: 8px 15px;
    //     background-color: #1a1a1a;
    //     border-radius: 8px;
    //     border: 1px solid #00ff88;
    // }

    @media (max-width: 768px) {
        .pagination-container {
            gap: 8px;
            padding: 15px;
        }

        .pagination-btn {
            padding: 8px 15px;
            font-size: 12px;
        }

        .page-number {
            padding: 6px 10px;
            font-size: 12px;
            min-width: 35px;
        }

        .page-info {
            width: 100%;
            text-align: center;
            margin-left: 0;
            margin-top: 10px;
        }
    }

    @media (max-width: 480px) {
        .pagination-btn {
            padding: 6px 12px;
            font-size: 11px;
        }

        .page-number {
            padding: 5px 8px;
            font-size: 11px;
            min-width: 30px;
        }

        .page-numbers {
            gap: 3px;
        }
    }
`;
document.head.appendChild(paginationStyles);

// Ensure all download buttons behave like local downloads
// - For same-origin (relative) URLs: add `download` attribute and remove `target`.
// - For cross-origin URLs: try to fetch the resource and download as a blob; if that fails, open in a new tab as a fallback.
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('a.download-btn').forEach(anchor => {
        // normalize href
        let href = anchor.getAttribute('href');
        if (!href) return;

        try {
            const url = new URL(href, location.href);

            if (url.origin === location.origin) {
                // same-origin: set download attribute (derive filename) and remove target
                const parts = url.pathname.split('/').filter(Boolean);
                const filename = parts.length ? parts[parts.length - 1] : 'download';
                anchor.setAttribute('download', filename);
                anchor.removeAttribute('target');
            } else {
                // cross-origin: add safety rel and attach click handler to attempt fetch->download
                anchor.setAttribute('rel', 'noopener noreferrer');
                anchor.addEventListener('click', async (e) => {
                    // try to fetch and download as blob
                    e.preventDefault();
                    try {
                        const resp = await fetch(anchor.href, { mode: 'cors' });
                        if (!resp.ok) throw new Error('Network response not ok');
                        const blob = await resp.blob();
                        const suggested = anchor.getAttribute('download') || (anchor.href.split('/').pop() || 'download');
                        const blobUrl = URL.createObjectURL(blob);
                        const tmp = document.createElement('a');
                        tmp.href = blobUrl;
                        tmp.download = suggested;
                        document.body.appendChild(tmp);
                        tmp.click();
                        tmp.remove();
                        URL.revokeObjectURL(blobUrl);
                    } catch (err) {
                        // fallback: open in new tab
                        window.open(anchor.href, '_blank', 'noopener noreferrer');
                    }
                });
            }
        } catch (err) {
            // malformed URL - ignore
        }
    });
});