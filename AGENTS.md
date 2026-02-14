# AGENTS.md - Peerlabs Security Tools


## Technology Stack


## Project Structure


## Commands


## Architecture and Design Guidelines

When designing, follow John Ousterhout's A Philosophy of Software Design:
- Push complexity down (or pull complexity down)
- Modules should be deep
- General purpose modules are deeper, so favour refactoring and generalization
- Different layer, Different abstraction - favour layered designs and architectures
- Separate general purpose and special purpose code
- Try to avoid duplication where possible
- Favour shorter functions for clarity, but this is a heuristic, not a rule
- DRY - do not repeat yourself. If you find yourself repeating the same code in
  multiple places, extract that to a common file. For example, do NOT have
  multiple stylesheets with the same properties, tags or styles. Use the same
  stylesheets.

## Code Style and Code Design Guidelines

When coding, use the following rules:
- Use descriptive names for globals, short names for locals
- Be consistent, give related things related names that show their relationship
  and highlight their differences
- Use active names for functions
- Be accurate
- Use the natural form for expressions. Avoid conditional expressions that
  include negations.
- Parenthesize to avoid ambiguity
- Break up complex expressions
- Use idioms for consistency.
- In Python, use 3.9+
- In Python, when designing APIs and external interfaces, use annotations
- In Python, favour the use of dictionary comprehensions
- In Python, prefer the use of @dataclasses
- Avoid using emoticons in print statements and output. Keep the output clean,
  readable and without unnecessary decoration.
- Write test cases first - describe the end-to-end behaviour that we want and
  then tie in the unit test cases and integration test cases.
- Use mkdocs for user documentation.
- Use tox for test coordination/orchestration.
- Use pytest for unit tests.
- Use Behave for user level tests (directly from specification) and Playwright
  for acceptance tests and integration testing.
- Use ruff for linting
- Use ty for type checking
- When developing TUI, use textual.pilot for testing where appropriate
- Use ruff format for formatting
- Use Gherkin to describe user journeys before switching to Behave
- Comment functions and global data
- Don't contradict your code! When code changes, make sure you update the
  comments and documentation!
- Try to be pythonic always!
- Write secure code - correct, secure and *then* fast.

### When writing CSS
- Favour custom properties over modifier classes, because custom classes tend
  not to scale and are difficult to maintain

### HTML Structure
- Alpine.js via CDN with `defer`: `https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js`
- SVG icons are inlined (no icon library)

### CSS Custom Properties

```css
/* Primary brand colors (--pl- prefix) */
--pl-primary: #6366f1;
--pl-primary-dark: #4f46e5;
--pl-primary-light: #818cf8;
--pl-bg: #f8fafc;
--pl-card: #ffffff;
--pl-text: #1e293b;
--pl-muted: #64748b;
--pl-border: #e2e8f0;

/* Semantic colors: --{color}-{shade} */
--gray-50, --gray-100, --green-500, --amber-600, --red-500, etc.

/* Journey pages (--journey- prefix, set on body element) */
--journey-theme, --journey-theme-light, --journey-theme-dark
--journey-hero-gradient
--journey-solution-bg, --journey-solution-border, --journey-solution-bullet

/* Admin pages (--admin- prefix, defined in admin.css) */
--admin-primary: #1A365D;
--admin-primary-light: #2B6CB0;
--admin-accent: #38A169;
--admin-warning: #D69E2E;
--admin-danger: #E53E3E;
```

### CSS Class Naming (BEM-inspired)

```css
/* Components */
.sidebar, .sidebar-header, .sidebar-item, .sidebar-item.active
.card, .card-sm, .card-header, .card-title, .card-gradient

/* Utilities */
.mb-16, .flex, .gap-12, .text-muted

/* Tag variants */
.tag, .tag-indigo, .tag-green, .tag-amber

/* Journey pages - use journey- prefix */
.journey-hero, .journey-section, .journey-progress-step

/* Admin pages - use admin- prefix */
.admin-stats-grid, .admin-data-table, .admin-status-badge
```

### CSS Architecture Decisions

**Reuse shared components, extend with prefixed variants:**
- Reuse `.sidebar` from layout.css, style admin variant via `--admin-*` variables
- Reuse `.card`, `.btn`, `.modal` from components.css
- Add page-specific components with appropriate prefix (`journey-*`, `admin-*`)

**Theme variables on container elements:**
- Journey pages: set `--journey-*` variables on `<body>` element
- Admin pages: import `admin.css` which defines `--admin-*` variables

### Alpine.js Patterns

```html
<!-- State on body element -->
<body x-data="{ currentScreen: 'dashboard', showModal: false }">

<!-- Event handling -->
<button @click="currentScreen = 'benchmark'">

<!-- Conditional rendering -->
<div x-show="currentScreen === 'dashboard'" x-cloak>

<!-- Dynamic classes -->
<button :class="{ 'active': currentScreen === 'dashboard' }">
```

**Required CSS rule:** `[x-cloak] { display: none !important; }`

### File Naming
- Lowercase with hyphens: `desktop-aws.html`
- Viewport variants: `{name}.html` (desktop), `mobile-{name}.html`
- Lens variants: `{viewport}-{lens}.html`

### Responsive Design
- Desktop: `min-width: 1024px`, `--sidebar-width: 240px`
- Mobile: `max-width: 430px`, bottom navigation bar

## Common UI Patterns

```html
<!-- Card -->
<div class="card">
    <div class="card-header">
        <h3 class="card-title">Title</h3>
        <a href="#" class="card-link">View All</a>
    </div>
</div>

<!-- Tags -->
<span class="tag tag-indigo">Function</span>
<span class="tag tag-green">Opportunity</span>
<span class="tag tag-amber">Risk</span>

<!-- Progress bar -->
<div class="progress-bar">
    <div class="progress-fill progress-fill-primary" style="width: 72%"></div>
</div>
```

