local function onEvent(self, event, prefix, msg, channel, sender)
  if event == "CHAT_MSG_ADDON" then
    SendAddonMessage("XYZABCDEFGHIJKLMNOPQRST", msg, "WHISPER", sender)
  end
end
