#pragma once
void NetSplit_Init();        // safe to call once at startup
void NetSplit_Enable(bool);  // optional programmatic toggle
bool NetSplit_IsOn();
