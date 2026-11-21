export default ({ filter }) => {
	filter('authenticate', (accountability) => ({
		...accountability,
		// Assign a custom role to anonymous accountability.
		// Keep the built-in anonymous/public role (role=null, user=null).
		origin: 'custom-anonymous-auth-test',
	}));
};
