-- Agent manifest: agents can describe their capabilities for discovery
ALTER TABLE agents ADD COLUMN manifest TEXT DEFAULT NULL;  -- JSON: { description, capabilities, tags, version }
