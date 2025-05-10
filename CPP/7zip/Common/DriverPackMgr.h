#pragma once
extern int dpmMain();
// Function declarations for top-level DPM logic
bool DpmInitialize7zLibrary();
bool dpGetInfs(class dp& oDP); // Use forward declaration or include dpmCommon.h

