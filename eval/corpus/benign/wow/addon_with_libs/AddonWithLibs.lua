local _, addon = ...
addon.db = {}
function addon:OnEnable()
    self.db.profile = LibStub("AceDB-3.0"):New("AddonDB")
end
