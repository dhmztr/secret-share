<script lang="ts">
import { fly, fade } from 'svelte/transition';
import { cubicOut } from 'svelte/easing';

type Mode = 'text' | 'file';
type Step = 'create' | 'success';

let mode = $state<Mode>('text');
let step = $state<Step>('create');
let isLoading = $state(false);

// Form fields
let textValue = $state('');
let fileInput = $state<HTMLInputElement | null>(null);
let selectedFile = $state<File | null>(null);
let maxViews = $state(1);
let customViewsEnabled = $state(false);
let customViewsValue = $state(10);
let passwordEnabled = $state(false);
let password = $state('');
let passwordVisible = $state(false);

// Success state
let generatedLink = $state('');
let copied = $state(false);
let submitError = $state('');

// Drag state
let isDragging = $state(false);

const viewOptions = [1, 5, 10, 25];
const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB

function handleFileSelect(files: FileList | null) {
if (files && files.length > 0) {
const file = files[0];
if (file.size > MAX_FILE_SIZE) {
submitError = `File is too large (${formatFileSize(file.size)}). Maximum allowed size is 25 MB.`;
selectedFile = null;
return;
}
submitError = '';
selectedFile = file;
}
}

function handleDrop(e: DragEvent) {
e.preventDefault();
isDragging = false;
if (e.dataTransfer?.files) {
handleFileSelect(e.dataTransfer.files);
}
}

function handleDragOver(e: DragEvent) {
e.preventDefault();
isDragging = true;
}

function handleDragLeave() {
isDragging = false;
}

function formatFileSize(bytes: number): string {
if (bytes < 1024) return bytes + ' B';
if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function getEffectiveMaxViews(): number {
if (customViewsEnabled) return customViewsValue;
return maxViews;
}

async function handleSubmit() {
submitError = '';
if (mode === 'text' && !textValue.trim()) {
    submitError = 'Please enter some text before generating a link.';
    return;
}
if (mode === 'file' && !selectedFile) {
    submitError = 'Please select a file before generating a link.';
    return;
}
if (mode === 'file' && selectedFile && selectedFile.size > MAX_FILE_SIZE) {
    submitError = `File is too large (${formatFileSize(selectedFile.size)}). Maximum allowed size is 25 MB.`;
    return;
}
if (passwordEnabled && !password.trim()) {
    submitError = 'Please enter a password or disable password protection.';
    return;
}
if (customViewsEnabled && (customViewsValue < 1 || customViewsValue > 1000 || !Number.isInteger(customViewsValue))) {
    submitError = 'Custom view count must be a whole number between 1 and 1000.';
    return;
}

isLoading = true;

// Simulate API call (replace with real endpoint when backend is ready)
await new Promise((resolve) => setTimeout(resolve, 1200));

const id = crypto.randomUUID().replace(/-/g, '').slice(0, 12);
generatedLink = `${window.location.origin}/s/${id}`;
step = 'success';
isLoading = false;
}

async function copyLink() {
try {
await navigator.clipboard.writeText(generatedLink);
copied = true;
setTimeout(() => (copied = false), 2000);
} catch {
// fallback: select input text
}
}

function reset() {
textValue = '';
selectedFile = null;
maxViews = 1;
customViewsEnabled = false;
customViewsValue = 10;
passwordEnabled = false;
password = '';
generatedLink = '';
copied = false;
submitError = '';
step = 'create';
mode = 'text';
}
</script>

<svelte:head>
<title>SecretShare — Create a secure link</title>
</svelte:head>

<main>
<div class="bg-grid" aria-hidden="true"></div>

<header>
<div class="logo">
<svg width="28" height="28" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
<rect x="4" y="12" width="20" height="14" rx="3" fill="url(#grad)" />
<path d="M9 12V9a5 5 0 0 1 10 0v3" stroke="url(#grad)" stroke-width="2.2" stroke-linecap="round" />
<circle cx="14" cy="19" r="2" fill="white" fill-opacity="0.9" />
<defs>
<linearGradient id="grad" x1="4" y1="4" x2="24" y2="26" gradientUnits="userSpaceOnUse">
<stop stop-color="#818cf8" />
<stop offset="1" stop-color="#c084fc" />
</linearGradient>
</defs>
</svg>
<span>SecretShare</span>
</div>
</header>

<div class="container">
{#if step === 'create'}
<div in:fly={{ y: 20, duration: 400, easing: cubicOut }}>
<div class="card">
<div class="card-header">
<h1>Create a secret link</h1>
<p>Share text or a file securely. The link self-destructs after the set number of views.</p>
</div>

<form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }}>
<!-- Mode Toggle -->
<div class="mode-toggle" role="tablist">
<button
role="tab"
type="button"
class="tab"
class:active={mode === 'text'}
aria-selected={mode === 'text'}
onclick={() => (mode = 'text')}
>
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
<polyline points="14 2 14 8 20 8" />
<line x1="16" y1="13" x2="8" y2="13" />
<line x1="16" y1="17" x2="8" y2="17" />
<polyline points="10 9 9 9 8 9" />
</svg>
Text
</button>
<button
role="tab"
type="button"
class="tab"
class:active={mode === 'file'}
aria-selected={mode === 'file'}
onclick={() => (mode = 'file')}
>
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
<path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
</svg>
File
</button>
</div>

<!-- Text Input -->
{#if mode === 'text'}
<div class="field" in:fade={{ duration: 200 }}>
<label for="secret-text">Secret text</label>
<textarea
id="secret-text"
bind:value={textValue}
placeholder="Enter your secret message here…"
rows="5"
required
></textarea>
</div>
{/if}

<!-- File Upload -->
{#if mode === 'file'}
<div class="field" in:fade={{ duration: 200 }}>
<!-- svelte-ignore a11y_label_has_associated_control -->
<label>File</label>
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div
class="drop-zone"
class:dragging={isDragging}
class:has-file={selectedFile !== null}
role="region"
aria-label="File drop zone"
ondrop={handleDrop}
ondragover={handleDragOver}
ondragleave={handleDragLeave}
onclick={() => fileInput?.click()}
onkeydown={(e) => e.key === 'Enter' && fileInput?.click()}
>
{#if selectedFile}
<div class="file-preview">
<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
<polyline points="14 2 14 8 20 8" />
</svg>
<div class="file-info">
<span class="file-name">{selectedFile.name}</span>
<span class="file-size">{formatFileSize(selectedFile.size)}</span>
</div>
<button
type="button"
class="remove-file"
aria-label="Remove file"
onclick={(e) => { e.stopPropagation(); selectedFile = null; }}
>
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
<line x1="18" y1="6" x2="6" y2="18" />
<line x1="6" y1="6" x2="18" y2="18" />
</svg>
</button>
</div>
{:else}
<div class="drop-prompt">
<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
<polyline points="16 16 12 12 8 16" />
<line x1="12" y1="12" x2="12" y2="21" />
<path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3" />
</svg>
<span>Drop a file here, or click to browse</span>
<span class="drop-hint">Any file type · Max 25 MB</span>
</div>
{/if}
</div>
<input
bind:this={fileInput}
type="file"
style="display: none"
onchange={(e) => handleFileSelect((e.target as HTMLInputElement).files)}
/>
</div>
{/if}

<!-- Max Views -->
<div class="field">
<!-- svelte-ignore a11y_label_has_associated_control -->
<label>Maximum views</label>
<div class="views-options">
{#each viewOptions as opt}
<button
type="button"
class="view-btn"
class:selected={!customViewsEnabled && maxViews === opt}
onclick={() => { maxViews = opt; customViewsEnabled = false; }}
aria-pressed={!customViewsEnabled && maxViews === opt}
>
{opt === 1 ? 'Once' : opt + '×'}
</button>
{/each}
<button
type="button"
class="view-btn custom-btn"
class:selected={customViewsEnabled}
onclick={() => (customViewsEnabled = true)}
aria-pressed={customViewsEnabled}
>
Custom
</button>
</div>
{#if customViewsEnabled}
<div class="custom-views" in:fly={{ y: -8, duration: 200 }}>
<input
type="number"
min="1"
max="1000"
bind:value={customViewsValue}
aria-label="Custom view count"
/>
<span class="views-label">views</span>
</div>
{/if}
<p class="field-hint">
The link will be permanently destroyed after
<strong>{getEffectiveMaxViews()}</strong>
{getEffectiveMaxViews() === 1 ? 'view' : 'views'}.
</p>
</div>

<!-- Password Protection -->
<div class="field">
<div class="toggle-row">
<div>
<label for="password-toggle" class="toggle-label">Password protection</label>
<p class="toggle-desc">Require a password to view the secret</p>
</div>
<button
id="password-toggle"
type="button"
class="toggle"
class:on={passwordEnabled}
onclick={() => (passwordEnabled = !passwordEnabled)}
aria-pressed={passwordEnabled}
aria-label="Toggle password protection"
>
<span class="thumb"></span>
</button>
</div>

{#if passwordEnabled}
<div class="password-field" in:fly={{ y: -8, duration: 200 }}>
<div class="password-input-wrap">
<svg class="input-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
<rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
<path d="M7 11V7a5 5 0 0 1 10 0v4" />
</svg>
<input
type={passwordVisible ? 'text' : 'password'}
bind:value={password}
placeholder="Enter password…"
aria-label="Password"
autocomplete="new-password"
/>
<button
type="button"
class="vis-toggle"
onclick={() => (passwordVisible = !passwordVisible)}
aria-label={passwordVisible ? 'Hide password' : 'Show password'}
>
{#if passwordVisible}
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
<path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
<line x1="1" y1="1" x2="23" y2="23" />
</svg>
{:else}
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
<circle cx="12" cy="12" r="3" />
</svg>
{/if}
</button>
</div>
</div>
{/if}
</div>

<!-- Submit -->
{#if submitError}
<p class="submit-error" role="alert">{submitError}</p>
{/if}
<button type="submit" class="btn-primary" disabled={isLoading || (mode === 'text' ? !textValue.trim() : !selectedFile) || (passwordEnabled && !password.trim())}>
{#if isLoading}
<span class="spinner" aria-hidden="true"></span>
Generating link…
{:else}
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
<path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
</svg>
Generate secret link
{/if}
</button>
</form>
</div>

<div class="features">
<div class="feature">
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
</svg>
<span>End-to-end encrypted</span>
</div>
<div class="feature">
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
<polyline points="3 6 5 6 21 6" />
<path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" />
</svg>
<span>Auto-destructs after viewing</span>
</div>
<div class="feature">
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
<circle cx="12" cy="12" r="10" />
<polyline points="12 6 12 12 16 14" />
</svg>
<span>No account required</span>
</div>
</div>
</div>

{:else}
<!-- Success State -->
<div in:fly={{ y: 20, duration: 400, easing: cubicOut }}>
<div class="card success-card">
<div class="success-icon" aria-hidden="true">
<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
<polyline points="20 6 9 17 4 12" />
</svg>
</div>
<h1>Your secret link is ready!</h1>
<p class="success-subtitle">
Share this link. It will self-destruct after
<strong>{getEffectiveMaxViews()}</strong>
{getEffectiveMaxViews() === 1 ? 'view' : 'views'}.
</p>

<div class="link-box">
<input type="text" readonly value={generatedLink} aria-label="Generated link" onclick={(e) => (e.target as HTMLInputElement).select()} />
<button type="button" class="copy-btn" class:copied onclick={copyLink} aria-label="Copy link">
{#if copied}
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
<polyline points="20 6 9 17 4 12" />
</svg>
Copied!
{:else}
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
<rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
</svg>
Copy link
{/if}
</button>
</div>

<div class="meta-pills">
<div class="pill">
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
<circle cx="12" cy="12" r="3" />
</svg>
{getEffectiveMaxViews()} {getEffectiveMaxViews() === 1 ? 'view' : 'views'} max
</div>
{#if passwordEnabled && password}
<div class="pill">
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
<rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
<path d="M7 11V7a5 5 0 0 1 10 0v4" />
</svg>
Password protected
</div>
{/if}
<div class="pill">
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
{#if mode === 'text'}
<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
<polyline points="14 2 14 8 20 8" />
{:else}
<path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
{/if}
</svg>
{mode === 'text' ? 'Text' : selectedFile?.name ?? 'File'}
</div>
</div>

<button type="button" class="btn-outline" onclick={reset}>
Create another secret
</button>
</div>
</div>
{/if}
</div>

<footer>
<p>Your secrets are encrypted and never stored in plain text.</p>
</footer>
</main>

<style>
:global(*) {
box-sizing: border-box;
margin: 0;
padding: 0;
}

:global(body) {
background-color: #0a0a0f;
color: #e2e4f0;
font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
font-size: 15px;
line-height: 1.6;
min-height: 100vh;
-webkit-font-smoothing: antialiased;
}

main {
min-height: 100vh;
display: flex;
flex-direction: column;
align-items: center;
padding: 0 1rem 2rem;
position: relative;
overflow: hidden;
}

.bg-grid {
position: fixed;
inset: 0;
background-image:
linear-gradient(rgba(129, 140, 248, 0.04) 1px, transparent 1px),
linear-gradient(90deg, rgba(129, 140, 248, 0.04) 1px, transparent 1px);
background-size: 40px 40px;
pointer-events: none;
z-index: 0;
}

:global(body)::before {
content: '';
position: fixed;
top: -30vh;
left: 50%;
transform: translateX(-50%);
width: 80vw;
height: 60vh;
background: radial-gradient(ellipse at center, rgba(129, 140, 248, 0.12) 0%, rgba(192, 132, 252, 0.06) 40%, transparent 70%);
pointer-events: none;
z-index: 0;
}

header {
width: 100%;
max-width: 520px;
padding: 1.5rem 0 0.5rem;
position: relative;
z-index: 1;
}

.logo {
display: flex;
align-items: center;
gap: 0.6rem;
font-weight: 600;
font-size: 1.1rem;
color: #e2e4f0;
letter-spacing: -0.01em;
}

.container {
width: 100%;
max-width: 520px;
position: relative;
z-index: 1;
padding-top: 1.5rem;
}

.card {
background: rgba(17, 17, 28, 0.85);
border: 1px solid rgba(255, 255, 255, 0.07);
border-radius: 20px;
padding: 2rem;
backdrop-filter: blur(20px);
box-shadow:
0 0 0 1px rgba(129, 140, 248, 0.05),
0 20px 60px rgba(0, 0, 0, 0.5),
0 1px 0 rgba(255, 255, 255, 0.04) inset;
}

.card-header {
margin-bottom: 1.75rem;
}

.card-header h1 {
font-size: 1.5rem;
font-weight: 700;
letter-spacing: -0.03em;
margin-bottom: 0.4rem;
background: linear-gradient(135deg, #e2e4f0 0%, #a5b4fc 100%);
-webkit-background-clip: text;
-webkit-text-fill-color: transparent;
background-clip: text;
}

.card-header p {
color: #6b7280;
font-size: 0.875rem;
}

form {
display: flex;
flex-direction: column;
gap: 1.5rem;
}

.mode-toggle {
display: flex;
background: rgba(255, 255, 255, 0.04);
border: 1px solid rgba(255, 255, 255, 0.07);
border-radius: 10px;
padding: 3px;
gap: 3px;
}

.tab {
flex: 1;
display: flex;
align-items: center;
justify-content: center;
gap: 0.5rem;
padding: 0.5rem 1rem;
border: none;
border-radius: 8px;
font-size: 0.875rem;
font-weight: 500;
cursor: pointer;
transition: all 0.2s ease;
color: #6b7280;
background: transparent;
font-family: inherit;
}

.tab.active {
background: rgba(129, 140, 248, 0.15);
color: #a5b4fc;
box-shadow: 0 0 0 1px rgba(129, 140, 248, 0.2);
}

.tab:hover:not(.active) {
color: #9ca3af;
background: rgba(255, 255, 255, 0.04);
}

.field {
display: flex;
flex-direction: column;
gap: 0.5rem;
}

.field > label {
font-size: 0.8125rem;
font-weight: 500;
color: #9ca3af;
letter-spacing: 0.02em;
text-transform: uppercase;
}

.field-hint {
font-size: 0.8125rem;
color: #4b5563;
}

.field-hint strong {
color: #818cf8;
}

textarea {
width: 100%;
resize: vertical;
min-height: 120px;
padding: 0.875rem 1rem;
background: rgba(255, 255, 255, 0.04);
border: 1px solid rgba(255, 255, 255, 0.08);
border-radius: 12px;
color: #e2e4f0;
font-family: inherit;
font-size: 0.9375rem;
line-height: 1.6;
transition: border-color 0.2s, box-shadow 0.2s;
outline: none;
}

textarea:focus {
border-color: rgba(129, 140, 248, 0.4);
box-shadow: 0 0 0 3px rgba(129, 140, 248, 0.08);
}

textarea::placeholder {
color: #374151;
}

.drop-zone {
border: 1.5px dashed rgba(255, 255, 255, 0.1);
border-radius: 12px;
padding: 1.75rem;
cursor: pointer;
transition: all 0.2s ease;
background: rgba(255, 255, 255, 0.02);
}

.drop-zone:hover,
.drop-zone.dragging {
border-color: rgba(129, 140, 248, 0.5);
background: rgba(129, 140, 248, 0.05);
}

.drop-zone.has-file {
border-style: solid;
border-color: rgba(129, 140, 248, 0.3);
background: rgba(129, 140, 248, 0.05);
}

.drop-prompt {
display: flex;
flex-direction: column;
align-items: center;
gap: 0.5rem;
color: #4b5563;
text-align: center;
}

.drop-prompt svg {
color: #374151;
}

.drop-prompt span {
font-size: 0.9375rem;
color: #6b7280;
}

.drop-hint {
font-size: 0.8125rem !important;
color: #374151 !important;
}

.file-preview {
display: flex;
align-items: center;
gap: 0.875rem;
}

.file-preview > svg {
color: #818cf8;
flex-shrink: 0;
}

.file-info {
flex: 1;
min-width: 0;
display: flex;
flex-direction: column;
gap: 0.15rem;
}

.file-name {
font-size: 0.875rem;
font-weight: 500;
color: #d1d5db;
white-space: nowrap;
overflow: hidden;
text-overflow: ellipsis;
}

.file-size {
font-size: 0.75rem;
color: #6b7280;
}

.remove-file {
flex-shrink: 0;
width: 28px;
height: 28px;
display: flex;
align-items: center;
justify-content: center;
border: none;
border-radius: 6px;
background: rgba(255, 255, 255, 0.06);
color: #6b7280;
cursor: pointer;
transition: all 0.15s ease;
}

.remove-file:hover {
background: rgba(239, 68, 68, 0.15);
color: #f87171;
}

.views-options {
display: flex;
gap: 0.5rem;
flex-wrap: wrap;
}

.view-btn {
padding: 0.4375rem 0.875rem;
border: 1px solid rgba(255, 255, 255, 0.08);
border-radius: 8px;
background: rgba(255, 255, 255, 0.04);
color: #6b7280;
font-family: inherit;
font-size: 0.875rem;
font-weight: 500;
cursor: pointer;
transition: all 0.15s ease;
}

.view-btn:hover {
border-color: rgba(129, 140, 248, 0.3);
color: #a5b4fc;
}

.view-btn.selected {
background: rgba(129, 140, 248, 0.15);
border-color: rgba(129, 140, 248, 0.35);
color: #a5b4fc;
}

.custom-views {
display: flex;
align-items: center;
gap: 0.625rem;
margin-top: 0.25rem;
}

.custom-views input {
width: 90px;
padding: 0.4375rem 0.75rem;
background: rgba(255, 255, 255, 0.05);
border: 1px solid rgba(129, 140, 248, 0.3);
border-radius: 8px;
color: #e2e4f0;
font-family: inherit;
font-size: 0.9375rem;
outline: none;
transition: border-color 0.2s;
}

.custom-views input:focus {
border-color: rgba(129, 140, 248, 0.6);
}

.views-label {
font-size: 0.875rem;
color: #6b7280;
}

.toggle-row {
display: flex;
align-items: center;
justify-content: space-between;
gap: 1rem;
}

.toggle-label {
font-size: 0.9rem;
font-weight: 500;
color: #d1d5db;
display: block;
margin-bottom: 0.1rem;
}

.toggle-desc {
font-size: 0.8125rem;
color: #4b5563;
}

.toggle {
flex-shrink: 0;
width: 44px;
height: 24px;
border-radius: 12px;
border: 1px solid rgba(255, 255, 255, 0.1);
background: rgba(255, 255, 255, 0.08);
cursor: pointer;
position: relative;
transition: all 0.2s ease;
padding: 0;
}

.toggle.on {
background: rgba(129, 140, 248, 0.3);
border-color: rgba(129, 140, 248, 0.5);
}

.thumb {
position: absolute;
top: 2px;
left: 2px;
width: 18px;
height: 18px;
border-radius: 50%;
background: #6b7280;
transition: all 0.2s cubic-bezier(0.34, 1.56, 0.64, 1);
}

.toggle.on .thumb {
transform: translateX(20px);
background: #818cf8;
}

.password-field {
margin-top: 0.25rem;
}

.password-input-wrap {
position: relative;
display: flex;
align-items: center;
}

.input-icon {
position: absolute;
left: 0.875rem;
color: #4b5563;
pointer-events: none;
}

.password-input-wrap input {
width: 100%;
padding: 0.625rem 2.75rem 0.625rem 2.5rem;
background: rgba(255, 255, 255, 0.04);
border: 1px solid rgba(255, 255, 255, 0.08);
border-radius: 10px;
color: #e2e4f0;
font-family: inherit;
font-size: 0.9375rem;
outline: none;
transition: border-color 0.2s, box-shadow 0.2s;
}

.password-input-wrap input:focus {
border-color: rgba(129, 140, 248, 0.4);
box-shadow: 0 0 0 3px rgba(129, 140, 248, 0.08);
}

.password-input-wrap input::placeholder {
color: #374151;
}

.vis-toggle {
position: absolute;
right: 0.75rem;
width: 28px;
height: 28px;
display: flex;
align-items: center;
justify-content: center;
border: none;
background: transparent;
color: #4b5563;
cursor: pointer;
transition: color 0.15s;
}

.vis-toggle:hover {
color: #9ca3af;
}

.submit-error {
font-size: 0.8125rem;
color: #f87171;
padding: 0.5rem 0.75rem;
background: rgba(239, 68, 68, 0.08);
border: 1px solid rgba(239, 68, 68, 0.2);
border-radius: 8px;
}

.btn-primary {
display: flex;
align-items: center;
justify-content: center;
gap: 0.5rem;
width: 100%;
padding: 0.875rem 1.5rem;
background: linear-gradient(135deg, #6366f1 0%, #818cf8 50%, #a855f7 100%);
border: none;
border-radius: 12px;
color: white;
font-family: inherit;
font-size: 0.9375rem;
font-weight: 600;
cursor: pointer;
transition: all 0.2s ease;
letter-spacing: -0.01em;
box-shadow: 0 4px 24px rgba(99, 102, 241, 0.25);
position: relative;
overflow: hidden;
}

.btn-primary::before {
content: '';
position: absolute;
inset: 0;
background: rgba(255, 255, 255, 0);
transition: background 0.2s;
}

.btn-primary:hover:not(:disabled)::before {
background: rgba(255, 255, 255, 0.08);
}

.btn-primary:active:not(:disabled) {
transform: translateY(1px);
box-shadow: 0 2px 12px rgba(99, 102, 241, 0.2);
}

.btn-primary:disabled {
opacity: 0.4;
cursor: not-allowed;
box-shadow: none;
}

.spinner {
width: 16px;
height: 16px;
border: 2px solid rgba(255, 255, 255, 0.3);
border-top-color: white;
border-radius: 50%;
animation: spin 0.7s linear infinite;
}

@keyframes spin {
to { transform: rotate(360deg); }
}

.features {
display: flex;
justify-content: center;
gap: 1.5rem;
flex-wrap: wrap;
margin-top: 1.25rem;
}

.feature {
display: flex;
align-items: center;
gap: 0.4rem;
font-size: 0.8125rem;
color: #4b5563;
}

.feature svg {
color: #374151;
}

.success-card {
text-align: center;
padding: 2.5rem 2rem;
}

.success-icon {
width: 64px;
height: 64px;
border-radius: 50%;
background: rgba(129, 140, 248, 0.12);
border: 1px solid rgba(129, 140, 248, 0.25);
display: flex;
align-items: center;
justify-content: center;
margin: 0 auto 1.5rem;
color: #818cf8;
}

.success-card h1 {
font-size: 1.4rem;
font-weight: 700;
letter-spacing: -0.03em;
background: linear-gradient(135deg, #e2e4f0 0%, #a5b4fc 100%);
-webkit-background-clip: text;
-webkit-text-fill-color: transparent;
background-clip: text;
margin-bottom: 0.5rem;
}

.success-subtitle {
color: #6b7280;
font-size: 0.875rem;
margin-bottom: 1.75rem;
}

.success-subtitle strong {
color: #818cf8;
}

.link-box {
display: flex;
gap: 0.5rem;
margin-bottom: 1.25rem;
background: rgba(255, 255, 255, 0.03);
border: 1px solid rgba(255, 255, 255, 0.07);
border-radius: 12px;
padding: 0.5rem;
}

.link-box input {
flex: 1;
min-width: 0;
padding: 0.5rem 0.625rem;
background: transparent;
border: none;
color: #a5b4fc;
font-family: 'SF Mono', 'Fira Code', monospace;
font-size: 0.8125rem;
outline: none;
overflow: hidden;
text-overflow: ellipsis;
white-space: nowrap;
}

.copy-btn {
display: flex;
align-items: center;
gap: 0.4rem;
padding: 0.5rem 0.875rem;
border: none;
border-radius: 8px;
background: rgba(129, 140, 248, 0.15);
color: #a5b4fc;
font-family: inherit;
font-size: 0.8125rem;
font-weight: 500;
cursor: pointer;
transition: all 0.15s ease;
white-space: nowrap;
flex-shrink: 0;
}

.copy-btn:hover {
background: rgba(129, 140, 248, 0.25);
}

.copy-btn.copied {
background: rgba(52, 211, 153, 0.15);
color: #6ee7b7;
}

.meta-pills {
display: flex;
justify-content: center;
flex-wrap: wrap;
gap: 0.5rem;
margin-bottom: 1.75rem;
}

.pill {
display: flex;
align-items: center;
gap: 0.35rem;
padding: 0.3rem 0.75rem;
background: rgba(255, 255, 255, 0.04);
border: 1px solid rgba(255, 255, 255, 0.07);
border-radius: 20px;
font-size: 0.8125rem;
color: #6b7280;
}

.btn-outline {
display: flex;
align-items: center;
justify-content: center;
gap: 0.5rem;
width: 100%;
padding: 0.75rem 1.5rem;
background: transparent;
border: 1px solid rgba(255, 255, 255, 0.1);
border-radius: 12px;
color: #6b7280;
font-family: inherit;
font-size: 0.9375rem;
font-weight: 500;
cursor: pointer;
transition: all 0.15s ease;
}

.btn-outline:hover {
border-color: rgba(129, 140, 248, 0.3);
color: #a5b4fc;
background: rgba(129, 140, 248, 0.05);
}

footer {
margin-top: auto;
padding: 2rem 0 0;
text-align: center;
font-size: 0.8125rem;
color: #374151;
position: relative;
z-index: 1;
}

@media (max-width: 540px) {
.card {
padding: 1.5rem;
border-radius: 16px;
}

.features {
gap: 0.875rem;
}

.views-options {
gap: 0.375rem;
}
}
</style>
