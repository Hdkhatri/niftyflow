/**
 * Loading Spinner Utility Functions
 * Reusable loading overlay management for all pages
 * 
 * Usage:
 * - showLoading() - Show the loading spinner
 * - hideLoading() - Hide the loading spinner
 * - setLoadingText(title, subtitle) - Update the loading text
 */

function showLoading(title, subtitle) {
    const overlay = document.getElementById('loadingOverlay');
    if (!overlay) {
        console.warn('Loading overlay element not found. Make sure loading-spinner.html is included.');
        return;
    }
    
    // Update text if provided
    if (title || subtitle) {
        setLoadingText(title, subtitle);
    }
    
    overlay.classList.add('active');
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (!overlay) {
        console.warn('Loading overlay element not found.');
        return;
    }
    
    overlay.classList.remove('active');
}

function setLoadingText(title, subtitle) {
    const titleElement = document.querySelector('.loading-text');
    const subtitleElement = document.querySelector('.loading-subtext');
    
    if (title && titleElement) {
        titleElement.textContent = title;
    }
    
    if (subtitle && subtitleElement) {
        subtitleElement.textContent = subtitle;
    }
}

function toggleLoading(shouldShow, title, subtitle) {
    if (shouldShow) {
        showLoading(title, subtitle);
    } else {
        hideLoading();
    }
}

// Auto-hide on fetch errors (with try-catch wrapper)
function fetchWithLoading(url, options = {}, title = 'Loading...', subtitle = 'Please wait') {
    showLoading(title, subtitle);
    
    return fetch(url, options)
        .then(response => {
            hideLoading();
            return response;
        })
        .catch(error => {
            hideLoading();
            throw error;
        });
}
