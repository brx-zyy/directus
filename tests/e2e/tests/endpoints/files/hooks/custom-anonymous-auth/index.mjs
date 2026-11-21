export default ({ filter }) => {
	filter('authenticate', (accountability) => ({
		...accountability,
		// Force the authenticate filter to return a custom accountability object.
		// Keep the built-in anonymous/public role (role=null, user=null).
		origin: 'custom-anonymous-auth-test',
	}));
};
