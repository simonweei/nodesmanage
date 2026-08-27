ALTER TABLE profiles ADD COLUMN protocols_json TEXT;

UPDATE profiles
SET protocols_json = json_array(json_object('type', type, 'settings', json(settings_json)));
