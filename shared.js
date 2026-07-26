// Utilities shared by index.html and admin/index.html — confirmed byte-identical between the two
// before being extracted here.
const API_BASE = 'https://aitit-training-os.david-damjakob.workers.dev';
function escapeHtml(s){ return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
