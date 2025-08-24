// Strict mode for better performance and error catching
'use strict';

// Navbar scroll effect with throttling
let navbar = document.querySelector('.navbar');
let lastScroll = 0;
let ticking = false;

function updateNavbar() {
  const currentScroll = window.pageYOffset;
  
  if (currentScroll > 50) {
    navbar.classList.add('scrolled');
  } else {
    navbar.classList.remove('scrolled');
  }
  
  lastScroll = currentScroll;
  ticking = false;
}

window.addEventListener('scroll', () => {
  if (!ticking) {
    window.requestAnimationFrame(updateNavbar);
    ticking = true;
  }
});

// Mobile menu toggle with animation
const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
const mobileMenu = document.querySelector('.mobile-menu');
let menuOpen = false;

mobileMenuBtn?.addEventListener('click', () => {
  menuOpen = !menuOpen;
  mobileMenuBtn.classList.toggle('active');
  mobileMenu.classList.toggle('active');
  document.body.style.overflow = menuOpen ? 'hidden' : '';
  
  // Accessibility
  mobileMenuBtn.setAttribute('aria-expanded', menuOpen);
});

// Close mobile menu on link click
document.querySelectorAll('.mobile-link').forEach(link => {
  link.addEventListener('click', () => {
    menuOpen = false;
    mobileMenuBtn.classList.remove('active');
    mobileMenu.classList.remove('active');
    document.body.style.overflow = '';
    mobileMenuBtn.setAttribute('aria-expanded', 'false');
  });
});

// Smooth scroll for navigation links with offset
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function (e) {
    e.preventDefault();
    const targetId = this.getAttribute('href');
    if (targetId === '#') return;
    
    const target = document.querySelector(targetId);
    if (target) {
      const offset = 100; // Account for fixed navbar and security bar
      const targetPosition = target.offsetTop - offset;
      
      window.scrollTo({
        top: targetPosition,
        behavior: 'smooth'
      });
      
      // Close mobile menu if open
      if (menuOpen) {
        menuOpen = false;
        mobileMenuBtn.classList.remove('active');
        mobileMenu.classList.remove('active');
        document.body.style.overflow = '';
      }
    }
  });
});

// Simple AOS (Animate On Scroll) implementation with IntersectionObserver
class SimpleAOS {
  constructor() {
    this.elements = document.querySelectorAll('[data-aos]');
    this.observer = null;
    this.init();
  }
  
  init() {
    // Use IntersectionObserver for better performance
    const options = {
      threshold: 0.1,
      rootMargin: '0px 0px -100px 0px'
    };
    
    this.observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const element = entry.target;
          const delay = element.getAttribute('data-aos-delay') || 0;
          
          setTimeout(() => {
            element.classList.add('aos-animate');
          }, delay);
          
          // Stop observing once animated
          this.observer.unobserve(element);
        }
      });
    }, options);
    
    // Start observing all elements
    this.elements.forEach(element => {
      this.observer.observe(element);
    });
  }
}

// Initialize animations when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new SimpleAOS();
  
  // Animate hero elements immediately
  const heroElements = document.querySelectorAll('.hero [data-aos]');
  heroElements.forEach((el, index) => {
    setTimeout(() => {
      el.classList.add('aos-animate');
    }, index * 100);
  });
});

// Parallax effect for gradient orbs with throttling
let mouseX = 0;
let mouseY = 0;
let parallaxTicking = false;

function updateParallax() {
  const orbs = document.querySelectorAll('.gradient-orb');
  const x = mouseX / window.innerWidth;
  const y = mouseY / window.innerHeight;
  
  orbs.forEach((orb, index) => {
    const speed = (index + 1) * 15;
    const xMove = (x - 0.5) * speed;
    const yMove = (y - 0.5) * speed;
    
    orb.style.transform = `translate(${xMove}px, ${yMove}px)`;
  });
  
  parallaxTicking = false;
}

document.addEventListener('mousemove', (e) => {
  mouseX = e.clientX;
  mouseY = e.clientY;
  
  if (!parallaxTicking) {
    window.requestAnimationFrame(updateParallax);
    parallaxTicking = true;
  }
});

// Copy code functionality with visual feedback
document.querySelectorAll('.code-copy').forEach(button => {
  button.addEventListener('click', async () => {
    const codeBlock = button.closest('.code-block').querySelector('code');
    const text = codeBlock.textContent;
    
    try {
      await navigator.clipboard.writeText(text);
      
      // Visual feedback
      const originalText = button.textContent;
      button.textContent = 'Copied!';
      button.style.background = 'var(--success)';
      
      setTimeout(() => {
        button.textContent = originalText;
        button.style.background = '';
      }, 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
      button.textContent = 'Failed';
      button.style.background = 'var(--danger)';
      
      setTimeout(() => {
        button.textContent = 'Copy';
        button.style.background = '';
      }, 2000);
    }
  });
});

// Animate resistance bars when in view
const resistanceBars = document.querySelectorAll('.resistance-fill');
const resistanceObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const bar = entry.target;
      const width = bar.style.width;
      bar.style.width = '0';
      
      setTimeout(() => {
        bar.style.width = width;
      }, 100);
      
      resistanceObserver.unobserve(bar);
    }
  });
}, { threshold: 0.5 });

resistanceBars.forEach(bar => {
  resistanceObserver.observe(bar);
});

// Security indicator animation
const securityIndicator = document.querySelector('.security-indicator');
if (securityIndicator) {
  // Add random flicker effect
  setInterval(() => {
    if (Math.random() > 0.9) {
      securityIndicator.style.animation = 'none';
      setTimeout(() => {
        securityIndicator.style.animation = '';
      }, 100);
    }
  }, 3000);
}

// Performance monitoring (optional - remove in production)
if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
  window.addEventListener('load', () => {
    const perfData = performance.getEntriesByType('navigation')[0];
    console.log('Page Performance:', {
      domContentLoaded: Math.round(perfData.domContentLoadedEventEnd - perfData.domContentLoadedEventStart) + 'ms',
      loadComplete: Math.round(perfData.loadEventEnd - perfData.loadEventStart) + 'ms',
      domInteractive: Math.round(perfData.domInteractive) + 'ms',
      domComplete: Math.round(perfData.domComplete) + 'ms'
    });
  });
}

// Lazy load images if any (future enhancement)
if ('loading' in HTMLImageElement.prototype) {
  const images = document.querySelectorAll('img[loading="lazy"]');
  images.forEach(img => {
    img.src = img.dataset.src;
  });
} else {
  // Fallback for browsers that don't support lazy loading
  const script = document.createElement('script');
  script.src = 'https://cdnjs.cloudflare.com/ajax/libs/lazysizes/5.3.2/lazysizes.min.js';
  document.body.appendChild(script);
}

// Memory usage warning simulation (demonstration only)
let memoryWarningShown = false;
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && !memoryWarningShown) {
    // Check if user has been on page for more than 5 minutes
    const timeOnPage = performance.now();
    if (timeOnPage > 300000) { // 5 minutes
      console.log('Memory-safe encryption ensures no sensitive data persists in browser memory');
      memoryWarningShown = true;
    }
  }
});

// Add keyboard navigation for better accessibility
document.addEventListener('keydown', (e) => {
  // Escape key closes mobile menu
  if (e.key === 'Escape' && menuOpen) {
    menuOpen = false;
    mobileMenuBtn.classList.remove('active');
    mobileMenu.classList.remove('active');
    document.body.style.overflow = '';
  }
});

// Initialize everything when ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

function init() {
  // Add loaded class for animations
  document.body.classList.add('loaded');
  
  // Log security features (for demonstration)
  console.log('%c🔐 x4 Model Security Features Active', 'color: #34d399; font-size: 16px; font-weight: bold;');
  console.log('%c• Memory sanitization: Active\n• Clipboard protection: Active\n• Zero-residue encryption: Active', 'color: #7c8cff; font-size: 12px;');
  console.log('%c⚠️ Warning: Never paste code here unless you understand what it does!', 'color: #ef4444; font-size: 14px; font-weight: bold;');
}
