local function save_and_run()
  vim.cmd([[wa]])
  vim.cmd([[belowright split]])
  vim.cmd([[resize -4]])
  vim.cmd([[terminal cmake -S . -B ./build && cmake --build build && ./build/i3blocks]])
end

local function save_and_debug()
  vim.cmd([[wa]])
  vim.cmd([[terminal cmake -S . -B ./build && cmake --build build]])
  vim.cmd([[terminal cmake -S . -B ./build && cmake --build build && gdb -q ./build/i3blocks]])
end

local opts = { noremap = true, silent = true }
vim.keymap.set("n", "<C-R>", save_and_run, opts)
vim.keymap.set("n", "<F5>", save_and_debug, opts)
