local LIBSTUB_MAJOR, LIBSTUB_MINOR = "LibStub", 2
local LibStub = _G[LIBSTUB_MAJOR]
if not LibStub or LibStub.minor < LIBSTUB_MINOR then
    LibStub = LibStub or {libs = {}, minor = LIBSTUB_MINOR}
    _G[LIBSTUB_MAJOR] = LibStub
end
