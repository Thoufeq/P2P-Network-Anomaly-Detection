// Network Security ML Analysis - Main JavaScript

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('Network Security ML Analysis App Initialized');
    
    // Initialize tooltips if Bootstrap is available
    if (typeof bootstrap !== 'undefined') {
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
    
    // Initialize other components
    initializeFormValidation();
    initializeFileUpload();
    addLoadingStates();
});

// Form validation utilities
function initializeFormValidation() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
                showFormErrors(form);
            }
            form.classList.add('was-validated');
        });
    });
}

function showFormErrors(form) {
    const invalidFields = form.querySelectorAll(':invalid');
    if (invalidFields.length > 0) {
        invalidFields[0].focus();
        showNotification('Please fill in all required fields correctly.', 'error');
    }
}

// File upload enhancement
function initializeFileUpload() {
    const fileInputs = document.querySelectorAll('input[type="file"]');
    
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                validateCSVFile(file, input);
            }
        });
    });
}

function validateCSVFile(file, input) {
    // Check file type
    if (!file.name.toLowerCase().endsWith('.csv')) {
        showNotification('Please select a CSV file.', 'error');
        input.value = '';
        return false;
    }
    
    // Check file size (max 16MB)
    const maxSize = 16 * 1024 * 1024;
    if (file.size > maxSize) {
        showNotification('File size must be less than 16MB.', 'error');
        input.value = '';
        return false;
    }
    
    showNotification(`File "${file.name}" loaded successfully.`, 'success');
    return true;
}

// Loading states for buttons
function addLoadingStates() {
    const submitButtons = document.querySelectorAll('button[type="submit"]');
    
    submitButtons.forEach(button => {
        const form = button.closest('form');
        if (form) {
            form.addEventListener('submit', function() {
                setButtonLoading(button, true);
            });
        }
    });
}

function setButtonLoading(button, isLoading) {
    if (isLoading) {
        button.disabled = true;
        const originalText = button.innerHTML;
        button.setAttribute('data-original-text', originalText);
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';
    } else {
        button.disabled = false;
        const originalText = button.getAttribute('data-original-text');
        if (originalText) {
            button.innerHTML = originalText;
        }
    }
}

// Notification system
function showNotification(message, type = 'info', duration = 5000) {
    // Remove existing notifications
    const existingAlerts = document.querySelectorAll('.alert-notification');
    existingAlerts.forEach(alert => alert.remove());
    
    // Create notification
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show alert-notification`;
    alertDiv.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 9999; max-width: 400px;';
    
    alertDiv.innerHTML = `
        <i class="fas fa-${getIconForType(type)} me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(alertDiv);
    
    // Auto-dismiss after duration
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.classList.remove('show');
            setTimeout(() => alertDiv.remove(), 150);
        }
    }, duration);
}

function getIconForType(type) {
    const icons = {
        'success': 'check-circle',
        'error': 'exclamation-triangle',
        'warning': 'exclamation-circle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

// Utility functions for forms
function resetForm(formId) {
    const form = document.getElementById(formId);
    if (form) {
        form.reset();
        form.classList.remove('was-validated');
    }
}

function populateSampleData() {
    // This function can be called to populate forms with sample data
    const sampleData = {
        'Packet_Size': 602,
        'Transmission_Rate': 189.384208,
        'Latency': 13.39276514,
        'Protocol_Type': 1,
        'Active_Connections': 481,
        'CPU_Usage': 43.73503418,
        'Memory_Usage': 5763.534906,
        'Bandwidth_Utilization': 57.43797264,
        'Request_Response_Time': 0.142441543,
        'Auth_Failures': 9,
        'Access_Violations': 3,
        'Firewall_Blocks': 0,
        'IDS_Alerts': 8,
        'DWT_Feature_1': 0.023823202
    };
    
    Object.keys(sampleData).forEach(key => {
        const input = document.querySelector(`input[name="${key}"], select[name="${key}"]`);
        if (input) {
            input.value = sampleData[key];
        }
    });
}

// Chart utilities (if Chart.js is available)
function createSimpleChart(ctx, data, options = {}) {
    if (typeof Chart === 'undefined') {
        console.warn('Chart.js not loaded');
        return null;
    }
    
    const defaultOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'top',
            }
        }
    };
    
    return new Chart(ctx, {
        type: options.type || 'bar',
        data: data,
        options: { ...defaultOptions, ...options }
    });
}

// Error handling
window.addEventListener('error', function(e) {
    console.error('JavaScript Error:', e.error);
    // Don't show notification for every JS error in production
});

window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled Promise Rejection:', e.reason);
});

// Export functions for use in other scripts
window.NetworkSecurityApp = {
    showNotification,
    setButtonLoading,
    resetForm,
    populateSampleData,
    createSimpleChart,
    validateCSVFile
};

// Smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Add fade-in animation to cards on scroll
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('fade-in');
        }
    });
}, observerOptions);

// Observe all cards for fade-in animation
document.querySelectorAll('.card').forEach(card => {
    observer.observe(card);
});

console.log('Network Security ML Analysis - JavaScript loaded successfully');
