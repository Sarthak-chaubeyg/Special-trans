// Navbar scroll effect
let navbar = document.querySelector('.navbar');
let lastScroll = 0;

window.addEventListener('scroll', () => {
  const currentScroll = window.pageYOffset;
  
  if (currentScroll > 50) {
    navbar.classList.add('scrolled');
  } else {
    navbar.classList.remove('scrolled');
  }
  
  lastScroll = currentScroll;
});

// Mobile menu toggle
const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
const mobileMenu = document.querySelector('.mobile-menu');

mobileMenuBtn?.addEventListener('click', () => {
  mobileMenuBtn.classList.toggle('active');
  mobileMenu.classList.toggle('active');
  document.body.style.overflow = mobileMenu.classList.contains('active') ? 'hidden' : '';
});

// Close mobile menu on link click
document.querySelectorAll('.mobile-link').forEach(link => {
  link.addEventListener('click', () => {
    mobileMenuBtn.classList.remove('active');
    mobileMenu.classList.remove('active');
    document.body.style.overflow = '';
  });
});

// Smooth scroll for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function (e) {
    e.preventDefault();
    const target = document.querySelector(this.getAttribute('href'));
    if (target) {
      const offset = 80; // Account for fixed navbar
      const targetPosition = target.offsetTop - offset;
      window.scrollTo({
        top: targetPosition,
        behavior: 'smooth'
      });
    }
  });
});

// Simple AOS (Animate On Scroll) implementation
class SimpleAOS {
  constructor() {
    this.elements = document.querySelectorAll('[data-aos]');
    this.init();
  }
  
  init() {
    // Initial check
    this.checkElements();
    
    // Throttled scroll listener
    let ticking = false;
    window.addEventListener('scroll', () => {
      if (!ticking) {
        window.requestAnimationFrame(() => {
          this.checkElements();
          ticking = false;
        });
        ticking = true;
      }
    });
  }
  
  checkElements() {
    this.elements.forEach(element => {
      if (this.isInViewport(element) && !element.classList.contains('aos-animate')) {
        const delay = element.getAttribute('data-aos-delay') || 0;
        setTimeout(() => {
          element.classList.add('aos-animate');
        }, delay);
      }
    });
  }
  
  isInViewport(element) {
    const rect = element.getBoundingClientRect();
    const windowHeight = window.innerHeight || document.documentElement.clientHeight;
    const threshold = 100; // Trigger animation 100px before element enters viewport
    
    return (
      rect.top <= windowHeight - threshold &&
      rect.bottom >= 0
    );
  }
}

// Initialize animations
document.addEventListener('DOMContentLoaded', () => {
  new SimpleAOS();
  
  // Add loading animation to hero elements
  const heroElements = document.querySelectorAll('.hero [data-aos]');
  heroElements.forEach((el, index) => {
    setTimeout(() => {
      el.classList.add('aos-animate');
    }, index * 100);
  });
});

// Copy code functionality
document.querySelectorAll('pre code').forEach(block => {
  block.addEventListener('click', () => {
    const text = block.textContent;
    navigator.clipboard.writeText(text).then(() => {
      // Visual feedback
      const originalText = block.innerHTML;
      block.innerHTML = 'Copied to clipboard!';
      block.style.color = '#34d399';
      
      setTimeout(() => {
        block.innerHTML = originalText;
        block.style.color = '';
      }, 2000);
    });
  });
  
  // Add copy hint on hover
  block.style.cursor = 'pointer';
  block.title = 'Click to copy';
});

// Parallax effect for gradient orbs
document.addEventListener('mousemove', (e) => {
  const orbs = document.querySelectorAll('.gradient-orb');
  const x = e.clientX / window.innerWidth;
  const y = e.clientY / window.innerHeight;
  
  orbs.forEach((orb, index) => {
    const speed = (index + 1) * 10;
    const xMove = (x - 0.5) * speed;
    const yMove = (y - 0.5) * speed;
    
    orb.style.transform = `translate(${xMove}px, ${yMove}px)`;
  });
});

// Performance metrics (optional)
if ('performance' in window && 'measureUserAgentSpecificMemory' in performance) {
  // Log performance metrics for optimization
  window.addEventListener('load', () => {
    const perfData = performance.getEntriesByType('navigation')[0];
    console.log('Page Load Performance:', {
      domContentLoaded: perfData.domContentLoadedEventEnd - perfData.domContentLoadedEventStart,
      loadComplete: perfData.loadEventEnd - perfData.loadEventStart,
      domInteractive: perfData.domInteractive,
      domComplete: perfData.domComplete
    });
  });
}

// Intersection Observer for lazy loading (future enhancement)
const lazyLoadObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      // Load content when visible
      const element = entry.target;
      element.classList.add('loaded');
      lazyLoadObserver.unobserve(element);
    }
  });
}, {
  rootMargin: '50px'
});

// Observe elements that need lazy loading
document.querySelectorAll('[data-lazy]').forEach(el => {
  lazyLoadObserver.observe(el);
});