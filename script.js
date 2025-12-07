// ========================================
// BinaryShield - Enhanced Tools & Scripts JavaScript
// Features: Search (Title + Description), Pagination, Share Functionality
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
    setupShareModal();
    displayPage(currentPage);
});

// Initialize all tools from the DOM
function initializeTools() {
    const toolBoxes = document.querySelectorAll('.tool-box');
    allTools = Array.from(toolBoxes).map(box => ({
        element: box,
        title: box.getAttribute('data-title').toLowerCase(),
        description: box.getAttribute('data-description').toLowerCase(),
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
        
        // Re-attach share button listeners after adding HTML
        attachShareListeners();
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

// Perform search - Now searches BOTH title AND description
function performSearch(searchTerm) {
    const term = searchTerm.toLowerCase().trim();
    
    if (term === '') {
        // Show all tools
        filteredTools = [...allTools];
    } else {
        // Filter tools by title OR description
        filteredTools = allTools.filter(tool => 
            tool.title.includes(term) || tool.description.includes(term)
        );
    }
    
    // Reset to first page and display
    currentPage = 1;
    displayPage(1);
}

// ========================================
// Share Functionality
// ========================================

let currentShareData = {};

function setupShareModal() {
    const modal = document.getElementById('shareModal');
    const closeBtn = modal.querySelector('.share-modal-close');
    
    // Close modal on X button
    closeBtn.addEventListener('click', () => {
        modal.style.display = 'none';
        modal.setAttribute('aria-hidden', 'true');
    });
    
    // Close modal on outside click
    window.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
            modal.setAttribute('aria-hidden', 'true');
        }
    });
    
    // Close on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && modal.style.display === 'flex') {
            modal.style.display = 'none';
            modal.setAttribute('aria-hidden', 'true');
        }
    });
    
    // Share option handlers
    const shareOptions = modal.querySelectorAll('.share-option');
    shareOptions.forEach(option => {
        option.addEventListener('click', function() {
            const platform = this.getAttribute('data-platform');
            handleShare(platform);
        });
    });
}

function attachShareListeners() {
    const shareButtons = document.querySelectorAll('.share-btn');
    shareButtons.forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const toolName = this.getAttribute('data-tool');
            const toolUrl = this.getAttribute('data-url');
            openShareModal(toolName, toolUrl);
        });
    });
}

function openShareModal(toolName, toolUrl) {
    const modal = document.getElementById('shareModal');
    const toolNameElement = document.getElementById('shareToolName');
    
    currentShareData = {
        title: `${toolName} - BinaryShield Free Security Tool`,
        url: toolUrl,
        text: `Check out ${toolName} - a free ethical hacking tool from BinaryShield`
    };
    
    toolNameElement.textContent = toolName;
    modal.style.display = 'flex';
    modal.setAttribute('aria-hidden', 'false');
}

function handleShare(platform) {
    const { title, url, text } = currentShareData;
    const encodedUrl = encodeURIComponent(url);
    const encodedTitle = encodeURIComponent(title);
    const encodedText = encodeURIComponent(text);
    
    let shareUrl;
    
    switch(platform) {
        case 'twitter':
            shareUrl = `https://twitter.com/intent/tweet?text=${encodedText}&url=${encodedUrl}`;
            break;
        case 'facebook':
            shareUrl = `https://www.facebook.com/sharer/sharer.php?u=${encodedUrl}`;
            break;
        case 'linkedin':
            shareUrl = `https://www.linkedin.com/sharing/share-offsite/?url=${encodedUrl}`;
            break;
        case 'whatsapp':
            shareUrl = `https://wa.me/?text=${encodedText}%20${encodedUrl}`;
            break;
        case 'copy':
            copyToClipboard(url);
            return;
    }
    
    if (shareUrl) {
        window.open(shareUrl, '_blank', 'width=600,height=400');
    }
    
    // Close modal
    document.getElementById('shareModal').style.display = 'none';
}

function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            showCopyNotification('Link copied to clipboard!');
        }).catch(() => {
            fallbackCopyToClipboard(text);
        });
    } else {
        fallbackCopyToClipboard(text);
    }
}

function fallbackCopyToClipboard(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showCopyNotification('Link copied to clipboard!');
    } catch (err) {
        showCopyNotification('Failed to copy link');
    }
    
    document.body.removeChild(textArea);
}

function showCopyNotification(message) {
    const notification = document.createElement('div');
    notification.className = 'copy-notification';
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.add('show');
    }, 10);
    
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 2000);
}

// ========================================
// Add CSS for Pagination and Share Modal
// ========================================

const styles = document.createElement('style');
styles.textContent = `
    /* Pagination Styles */
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

    /* Share Button Styles */
    .share-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 35px;
        height: 35px;
        border-radius: 50%;
        background-color: #00ff88;
        color: #000000;
        border: none;
        font-size: 16px;
        cursor: pointer;
        transition: all 0.3s ease;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.5);
    }

    .share-btn:hover {
        background-color: #00cc6e;
        transform: scale(1.15) rotate(-5deg);
    }

    /* Share Modal Styles */
    .share-modal {
        display: none;
        position: fixed;
        z-index: 10000;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.8);
        justify-content: center;
        align-items: center;
        animation: fadeIn 0.3s ease;
    }

    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }

    .share-modal-content {
        background-color: #2e2e2e;
        padding: 30px;
        border-radius: 15px;
        max-width: 500px;
        width: 90%;
        position: relative;
        animation: slideUp 0.3s ease;
        box-shadow: 0 10px 40px rgba(255, 0, 0, 0.5);
    }

    @keyframes slideUp {
        from {
            transform: translateY(50px);
            opacity: 0;
        }
        to {
            transform: translateY(0);
            opacity: 1;
        }
    }

    .share-modal-close {
        position: absolute;
        top: 15px;
        right: 20px;
        font-size: 32px;
        font-weight: bold;
        color: #ff0000;
        background: none;
        border: none;
        cursor: pointer;
        transition: color 0.3s ease;
    }

    .share-modal-close:hover {
        color: #00ff88;
    }

    .share-modal-content h3 {
        color: #ff0000;
        font-size: 24px;
        margin-bottom: 10px;
        font-weight: 700;
    }

    .share-modal-content p {
        color: #00ff88;
        margin-bottom: 25px;
        font-size: 16px;
    }

    .share-buttons {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 15px;
    }

    .share-option {
        padding: 15px;
        background-color: #1a1a1a;
        color: #ffffff;
        border: 2px solid #ff0000;
        border-radius: 10px;
        font-family: 'Poppins', Arial, sans-serif;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
        display: flex;
        align-items: center;
        gap: 10px;
        justify-content: center;
    }

    .share-option:hover {
        background-color: #ff0000;
        transform: translateY(-3px);
        box-shadow: 0 5px 15px rgba(255, 0, 0, 0.4);
    }

    .share-option span {
        font-size: 20px;
    }

    /* Copy Notification */
    .copy-notification {
        position: fixed;
        bottom: 30px;
        left: 50%;
        transform: translateX(-50%) translateY(100px);
        background-color: #00ff88;
        color: #000000;
        padding: 15px 30px;
        border-radius: 8px;
        font-weight: 600;
        box-shadow: 0 5px 20px rgba(0, 255, 136, 0.5);
        z-index: 10001;
        opacity: 0;
        transition: all 0.3s ease;
    }

    .copy-notification.show {
        transform: translateX(-50%) translateY(0);
        opacity: 1;
    }

    /* Responsive Styles */
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

        .share-modal-content {
            padding: 25px;
        }

        .share-buttons {
            grid-template-columns: 1fr;
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

        .share-modal-content h3 {
            font-size: 20px;
        }
    }
`;
document.head.appendChild(styles);

// Ensure all download buttons behave like local downloads
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('a.download-btn').forEach(anchor => {
        let href = anchor.getAttribute('href');
        if (!href || href === '#') return;

        try {
            const url = new URL(href, location.href);

            if (url.origin === location.origin) {
                const parts = url.pathname.split('/').filter(Boolean);
                const filename = parts.length ? parts[parts.length - 1] : 'download';
                anchor.setAttribute('download', filename);
                anchor.removeAttribute('target');
            } else {
                anchor.setAttribute('rel', 'noopener noreferrer');
                anchor.addEventListener('click', async (e) => {
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
                        window.open(anchor.href, '_blank', 'noopener noreferrer');
                    }
                });
            }
        } catch (err) {
            // malformed URL - ignore
        }
    });
});